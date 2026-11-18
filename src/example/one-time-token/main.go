// Command one-time-token runs goauth with the one-time-token plugin: a signed-in user asks for a short-lived,
// single-use token (GET /api/auth/one-time-token/generate) and hands it to another client (a mobile app,
// another domain, a desktop app opened from the browser), which exchanges it for the same session
// (POST /api/auth/one-time-token/verify).
//
//	go run ./src/example/one-time-token       # http://localhost:8080/docs
//	go test ./src/example/one-time-token      # runs the flow end to end
package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	onetimetoken "github.com/better-go-auth/goauth/src/plugins/one-time-token"
	ottconfig "github.com/better-go-auth/goauth/src/plugins/one-time-token/config"
)

// newApp builds the example server. dbPath "" uses an in-memory database (tests).
func newApp(dbPath string) (*exkit.App, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, err
	}
	// Step 2: configure the plugin. Tokens are stored hashed in the verification table, live 2 minutes,
	// and every response that creates a session also carries a fresh token in the `set-ott` header
	ottPlugin := onetimetoken.New(ottconfig.OneTimeTokenConfig{
		ExpiresIn:                2 * time.Minute, // default 3 minutes
		StoreToken:               ottconfig.StoreTokenConfig{Mode: ottconfig.StoreTokenHashed},
		SetOttHeaderOnNewSession: true,
	})
	// Step 3: set goauth up with the plugin
	app, err := exkit.New(context.Background(), exkit.Options{
		DB:      db,
		Plugins: []plugin.Plugin{ottPlugin},
	})
	if err != nil {
		return nil, err
	}
	// Step 4: a protected route of your own
	app.AddMeRoute()
	return app, nil
}

func main() {
	dbPath := os.Getenv("SQLITE_DB")
	if dbPath == "" {
		dbPath = "one_time_token_example.db"
	}
	app, err := newApp(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
