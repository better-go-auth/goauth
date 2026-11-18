// Command access-token runs goauth with the access-token plugin, goauth's own (non better-auth) JWT flow:
// POST /api/auth/login returns a short-lived access token (JWT) and a refresh token (the session token),
// POST /api/auth/refresh trades the refresh token for a new pair, and your routes accept the access token
// as "Authorization: Bearer <jwt>" through the plugin's middleware. POST /api/auth/sign-out logs the client out
// (with the access token or the refresh token) and revokes the session behind it.
//
//	go run ./src/example/access-token        # http://localhost:8080/docs
//	go test ./src/example/access-token       # runs the flow end to end
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	accesstoken "github.com/better-go-auth/goauth/src/plugins/access-token"
	accesstokenconfig "github.com/better-go-auth/goauth/src/plugins/access-token/config"
	"github.com/better-go-auth/goauth/src/providers/authenticator"
	"github.com/danielgtaylor/huma/v2"
)

// codeSender delivers the verification code POST /api/auth/signup sends. The example only records it in
// the outbox (and the log); a real app emails it.
type codeSender struct{ out *exkit.Outbox }

func (s codeSender) SendVerificationCode(to, code string) error {
	s.out.Put("verification-code", to, code)
	return nil
}

// app is the example server plus the plugin, so the tests can reach both.
type app struct {
	*exkit.App
	AccessToken *accesstoken.Plugin
	Outbox      *exkit.Outbox
}

// newApp builds the example server. dbPath "" uses an in-memory database (tests).
func newApp(dbPath string) (*app, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, err
	}
	// Step 2: configure the plugin. AccessSecret defaults to a key derived from the core secret; set
	// it (JWT_ACCESS_SECRET) to sign access tokens with a key of their own.
	atPlugin := accesstoken.New(accesstokenconfig.AccessTokenConfig{
		Session: accesstokenconfig.SessionGoAuth{
			JWT: accesstokenconfig.SessionJWT{
				AccessSecret:    os.Getenv("JWT_ACCESS_SECRET"),
				AccessExpiresIn: 15 * time.Minute,
			},
		},
		// false (default): only routes that list AuthMiddleware() accept access tokens
		AutoRegisterMiddleware: false,
	})
	// Step 3: /signup sends a verification code through EmailVerification.GoAuth.CodeSender
	outbox := &exkit.Outbox{}
	base, err := exkit.New(context.Background(), exkit.Options{
		DB:      db,
		Plugins: []plugin.Plugin{atPlugin},
		Configure: func(c *config.AuthConfig) {
			c.EmailVerification.GoAuth.CodeSender = codeSender{out: outbox}
		},
	})
	if err != nil {
		return nil, err
	}
	a := &app{App: base, AccessToken: atPlugin, Outbox: outbox}
	// Step 4: routes of your own: the cookie-session route every example has and a route that accepts the
	// access token. Logging out needs no route of your own: POST /api/auth/sign-out accepts the access token,
	// the refresh token (Bearer or cookie) and revokes the session behind it.
	a.AddMeRoute()
	a.addJWTMeRoute()
	return a, nil
}

// addJWTMeRoute registers GET /api/example/jwt/me, protected by an access token.
func (a *app) addJWTMeRoute() {
	huma.Register(a.API, huma.Operation{
		OperationID: "Example_JWTMe",
		Method:      http.MethodGet,
		Path:        "/api/example/jwt/me",
		Summary:     "The signed-in user, from an access token (protected example route)",
		Tags:        []string{"Example"},
		// Step 1: AuthMiddleware verifies "Authorization: Bearer <access token>", checks the session behind it
		// is still alive and puts it in the context; Authenticate then rejects requests without a session
		// (it also still accepts the better-auth session cookie)
		Middlewares: huma.Middlewares{a.AccessToken.AuthMiddleware(), a.Auth.MiddlewareInt().Authenticate()},
	}, func(ctx context.Context, _ *struct{}) (*exkit.MeOutput, error) {
		// Step 2: read the session from the context, exactly like a cookie-protected route
		s, ok := authenticator.SessionFromContext(ctx)
		if !ok {
			return nil, huma.Error401Unauthorized("not signed in")
		}
		out := &exkit.MeOutput{}
		out.Body.UserID = s.Session.UserID
		out.Body.Role = s.User.Role
		out.Body.SessionID = s.Session.ID
		// Step 3: load the rest of the user
		u, err := a.Auth.Repositories().FindUserByID(ctx, s.Session.UserID)
		if err != nil {
			return nil, huma.Error500InternalServerError("load user")
		}
		out.Body.Email = u.Email
		return out, nil
	})
}

func main() {
	dbPath := os.Getenv("SQLITE_DB")
	if dbPath == "" {
		dbPath = "access_token_example.db"
	}
	a, err := newApp(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(a.Mux)
}
