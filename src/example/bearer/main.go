// Command bearer runs goauth with the bearer plugin: clients that can't keep cookies (mobile apps, CLIs,
// other servers) read the session token from the `set-auth-token` response header and send it back as
// `Authorization: Bearer <token>`. The plugin turns that header into the session cookie, so every goauth
// route and your own protected routes accept it.
//
//	go run ./src/example/bearer               # http://localhost:8080/docs
//	go test ./src/example/bearer              # runs the flow end to end
package main

import (
	"context"
	"log"
	"os"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
)

// newApp builds the example server. dbPath "" uses an in-memory database (tests).
func newApp(dbPath string) (*exkit.App, error) {
	// the default config requires signed tokens ("<token>.<signature>", the value of set-auth-token)
	return newAppWithConfig(dbPath, bearerconfig.DefaultConfig())
}

// newAppWithConfig builds the example server with a given bearer configuration.
func newAppWithConfig(dbPath string, cfg bearerconfig.BearerConfig) (*exkit.App, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, err
	}
	// Step 2: configure the plugin (RequireSignature nil or true = only signed tokens are accepted)
	bearerPlugin := bearer.New(cfg)
	// Step 3: set goauth up with the plugin
	app, err := exkit.New(context.Background(), exkit.Options{
		DB:      db,
		Plugins: []plugin.Plugin{bearerPlugin},
	})
	if err != nil {
		return nil, err
	}
	// Step 4: a protected route of your own; it accepts the session cookie or the bearer token
	app.AddMeRoute()
	return app, nil
}

func main() {
	dbPath := os.Getenv("SQLITE_DB")
	if dbPath == "" {
		dbPath = "bearer_example.db"
	}
	app, err := newApp(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
