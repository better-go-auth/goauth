// Command api-key runs goauth with the api-key plugin: signed-in users create API keys
// (POST /api/auth/api-key/create), and scripts call your own routes with the `x-api-key` header instead of a
// session cookie. Keys are stored hashed, rate limited per key and may carry permissions.
//
//	go run ./src/example/api-key            # http://localhost:8080/docs
//	go test ./src/example/api-key           # runs the flow end to end
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	apikey "github.com/better-go-auth/goauth/src/plugins/api-key"
	apikeyconfig "github.com/better-go-auth/goauth/src/plugins/api-key/config"
	"github.com/better-go-auth/goauth/src/providers/access"
	"github.com/danielgtaylor/huma/v2"
)

// ReportsOutput is the body of the example's GET /api/example/reports route.
type ReportsOutput struct {
	Body struct {
		UserID  string   `json:"userId"`
		KeyID   string   `json:"keyId"`
		Reports []string `json:"reports"`
	}
}

// newApp builds the example server and returns it with the plugin (for its Go API). dbPath "" uses an
// in-memory database (tests).
func newApp(dbPath string) (*exkit.App, *apikey.Plugin, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, nil, err
	}
	// Step 2: configure the plugin: "ex_" keys, metadata, 100 requests per minute per key, new keys may read
	// reports, and a key in x-api-key also authenticates goauth's own routes (get-session, ...)
	maxRequests := 100
	keys := apikey.New(apikeyconfig.Configuration{
		DefaultPrefix:           "ex_",
		EnableMetadata:          true,
		EnableSessionForAPIKeys: true,
		RateLimit:               apikeyconfig.RateLimit{TimeWindow: time.Minute, MaxRequests: &maxRequests},
		Permissions:             apikeyconfig.Permissions{DefaultPermissions: access.Statements{"reports": {"read"}}},
	})
	// Step 3: set goauth up with the plugin (the apikey table is created by goauth's migrator)
	app, err := exkit.New(context.Background(), exkit.Options{DB: db, Plugins: []plugin.Plugin{keys}})
	if err != nil {
		return nil, nil, err
	}
	// Step 4: routes of your own: one for sessions (cookie or key), one only for keys allowed to read reports
	app.AddMeRoute()
	huma.Register(app.API, huma.Operation{
		OperationID: "Example_Reports",
		Method:      http.MethodGet,
		Path:        "/api/example/reports",
		Summary:     "Reports (API key with reports:read)",
		Tags:        []string{"Example"},
		Middlewares: huma.Middlewares{keys.Middleware(apikey.MiddlewareOptions{Permissions: map[string][]string{"reports": {"read"}}})},
	}, func(ctx context.Context, _ *struct{}) (*ReportsOutput, error) {
		// the middleware stored the key and its owner's session in the request context
		k, _ := apikey.FromContext(ctx)
		sw, _ := apikey.SessionFromContext(ctx)
		out := &ReportsOutput{}
		out.Body.KeyID = k.ID
		out.Body.UserID = sw.User.ID
		out.Body.Reports = []string{"2026-q3", "2026-q4"}
		return out, nil
	})
	return app, keys, nil
}

func main() {
	dbPath := os.Getenv("SQLITE_DB")
	if dbPath == "" {
		dbPath = "api_key_example.db"
	}
	app, _, err := newApp(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
