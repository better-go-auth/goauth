// Command multi-session runs goauth with the multi-session plugin: one browser can be signed in as
// several users at once (like account switching in Gmail), list those sessions, switch the active one
// and revoke them.
//
//	go run ./src/example/multi-session       # http://localhost:8080/docs
//	go test ./src/example/multi-session      # runs the flow end to end
package main

import (
	"context"
	"log"
	"os"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	multisession "github.com/better-go-auth/goauth/src/plugins/multi-session"
	msconfig "github.com/better-go-auth/goauth/src/plugins/multi-session/config"
)

// newApp builds the example server. dbPath "" uses an in-memory database (tests).
func newApp(dbPath string) (*exkit.App, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, err
	}
	// Step 2: configure the plugin. MaximumSessions caps the accounts one browser can hold (default 5).
	// GoAuth.StrictDeviceCookie (off by default, as in better-auth) makes set-active / revoke require
	// the device cookie to hold exactly the requested token
	multiSessionPlugin := multisession.New(msconfig.MultiSessionConfig{
		MaximumSessions: 3,
		GoAuth:          msconfig.MultiSessionGoAuth{StrictDeviceCookie: true},
	})
	// Step 3: set goauth up with the plugin
	app, err := exkit.New(context.Background(), exkit.Options{
		DB:      db,
		Plugins: []plugin.Plugin{multiSessionPlugin},
	})
	if err != nil {
		return nil, err
	}
	// Step 4: a protected route of your own; it always sees the browser's active session
	app.AddMeRoute()
	return app, nil
}

func main() {
	dbPath := os.Getenv("SQLITE_DB")
	if dbPath == "" {
		dbPath = "multi_session_example.db"
	}
	app, err := newApp(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
