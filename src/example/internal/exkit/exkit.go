// Package exkit holds the small amount of wiring every plugin example shares: opening a database,
// mounting goauth on a Huma API, capturing outgoing emails/SMS, serving with graceful shutdown, and an
// HTTP client for the example tests. Each example under src/example/<plugin> builds its server with it,
// so the example code itself only shows what is specific to the plugin.
package exkit

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/config"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/providers/authenticator"
	"github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Secret is the example signing secret. Real deployments read it from BETTER_AUTH_SECRET instead.
const Secret = "example-secret-at-least-32-characters-long!"

// DefaultBaseURL is the base URL the examples run on (PORT changes the port).
const DefaultBaseURL = "http://localhost:8080"

// OpenDB opens a SQLite database: the file at path, or a private in-memory database when path is "".
func OpenDB(path string) (*gorm.DB, error) {
	// Step 1: a unique shared-cache name keeps every in-memory database (one per test) separate
	dsn := path
	if dsn == "" {
		dsn = fmt.Sprintf("file:example_%s?mode=memory&cache=shared", uuid.NewString())
	}
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		return nil, err
	}
	// Step 2: SQLite answers concurrent writers with "database is locked"; one connection serializes them
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	return db, nil
}

// Options configures an example server.
type Options struct {
	// DB is the database; nil opens a private in-memory SQLite database.
	DB *gorm.DB
	// BaseURL is the public URL of the server (default DefaultBaseURL).
	BaseURL string
	// Plugins are the goauth plugins under demonstration.
	Plugins []plugin.Plugin
	// Configure adjusts the AuthConfig before setup (e.g. email verification settings).
	Configure func(*config.AuthConfig)
}

// App is a running goauth instance: the auth object, the Huma API (to add your own routes) and the mux.
type App struct {
	Auth    *goauth.GoAuth
	API     huma.API
	Mux     *http.ServeMux
	DB      *gorm.DB
	BaseURL string
}

// New sets up goauth with the given plugins on a fresh Huma API.
func New(ctx context.Context, opts Options) (*App, error) {
	// Step 1: defaults (in-memory database, local base URL)
	if opts.DB == nil {
		db, err := OpenDB("")
		if err != nil {
			return nil, fmt.Errorf("exkit: open db: %w", err)
		}
		opts.DB = db
	}
	if opts.BaseURL == "" {
		opts.BaseURL = DefaultBaseURL
	}
	// Step 2: secondary storage (rate limits, caches); use Redis or similar in production
	store, err := memory.NewSecondaryStorage()
	if err != nil {
		return nil, fmt.Errorf("exkit: secondary storage: %w", err)
	}
	// Step 3: the core auth config every example shares
	authCfg := config.AuthConfig{
		BaseURL:        opts.BaseURL,
		Secret:         Secret,
		TrustedOrigins: []string{"http://localhost:*", "http://127.0.0.1:*"},
	}
	if opts.Configure != nil {
		opts.Configure(&authCfg)
	}
	// Step 4: mount goauth on a Huma API (routes under /api/auth, docs under /docs)
	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("goauth example", "1.0.0"))
	a, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
		Conn:             opts.DB,
		SecondaryStorage: store,
		AuthConfig:       authCfg,
		Plugins:          opts.Plugins,
	})
	if err != nil {
		return nil, fmt.Errorf("exkit: setup goauth: %w", err)
	}
	return &App{Auth: a, API: api, Mux: mux, DB: opts.DB, BaseURL: opts.BaseURL}, nil
}

// Serve listens on $PORT (default 8080) until SIGINT/SIGTERM, then shuts down gracefully.
func Serve(handler http.Handler) {
	// Step 1: start the server in the background
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	srv := &http.Server{Addr: ":" + port, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		log.Printf("listening on http://localhost:%s (OpenAPI docs: http://localhost:%s/docs)", port, port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()
	// Step 2: wait for a shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	// Step 3: let in-flight requests finish
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

// Outbox records the messages (emails, SMS, links) a plugin sends, and logs them. Examples pass its
// methods as the plugin's send callbacks so the codes can be read back, by a person in the log or by
// the tests through Last.
type Outbox struct {
	mu   sync.Mutex
	last map[string]string
}

// Put records value as the latest message of kind sent to to.
func (o *Outbox) Put(kind, to, value string) {
	o.mu.Lock()
	if o.last == nil {
		o.last = map[string]string{}
	}
	o.last[kind+"|"+to] = value
	o.mu.Unlock()
	log.Printf("[%s] to %s: %s", kind, to, value)
}

// Last returns the latest message of kind sent to to ("" when none).
func (o *Outbox) Last(kind, to string) string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.last[kind+"|"+to]
}

// MeOutput is the body of the example's protected GET /api/example/me route.
type MeOutput struct {
	Body struct {
		UserID    string `json:"userId"`
		Email     string `json:"email"`
		Role      string `json:"role"`
		SessionID string `json:"sessionId"`
	}
}

// AddMeRoute registers GET /api/example/me, a route of your own protected by goauth's session
// middleware: it answers 401 without a valid session and returns the signed-in user otherwise.
func (a *App) AddMeRoute() {
	huma.Register(a.API, huma.Operation{
		OperationID: "Example_Me",
		Method:      http.MethodGet,
		Path:        "/api/example/me",
		Summary:     "The signed-in user (protected example route)",
		Tags:        []string{"Example"},
		// Step 1: the Authenticate middleware resolves the session cookie / bearer token or rejects the request
		Middlewares: huma.Middlewares{a.Auth.MiddlewareInt().Authenticate()},
	}, func(ctx context.Context, _ *struct{}) (*MeOutput, error) {
		// Step 2: read the session the middleware stored in the request context; it carries the IDs, the
		// role and the active organization, not the whole user
		s, ok := authenticator.SessionFromContext(ctx)
		if !ok {
			return nil, huma.Error401Unauthorized("not signed in")
		}
		out := &MeOutput{}
		out.Body.UserID = s.Session.UserID
		out.Body.Role = s.User.Role
		out.Body.SessionID = s.Session.ID
		// Step 3: load the rest of the user from the repository when the route needs it
		u, err := a.Auth.Repositories().FindUserByID(ctx, s.Session.UserID)
		if err != nil {
			return nil, huma.Error500InternalServerError("load user")
		}
		out.Body.Email = u.Email
		return out, nil
	})
}
