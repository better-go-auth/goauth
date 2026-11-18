// Command haveibeenpwned runs goauth with the have-i-been-pwned plugin: new passwords on sign-up,
// change-password and reset-password are checked against the Pwned Passwords range API (k-anonymity: only
// the first five characters of the password's SHA-1 hash leave the server).
//
//	go run ./src/example/haveibeenpwned    # http://localhost:8080/docs (uses api.pwnedpasswords.com)
//	go test ./src/example/haveibeenpwned   # the flow end to end, against a fake range API
package main

import (
	"context"
	"log"
	"os"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/haveibeenpwned"
	hibpconfig "github.com/better-go-auth/goauth/src/plugins/haveibeenpwned/config"
)

// newApp builds the example server. dbPath "" uses an in-memory database (tests); apiURL "" uses the real
// range API.
func newApp(dbPath, apiURL string) (*exkit.App, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, err
	}
	// Step 2: configure the plugin (default paths: /sign-up/email, /change-password, /reset-password)
	hibpPlugin := haveibeenpwned.New(hibpconfig.HaveIBeenPwnedConfig{
		CustomPasswordCompromisedMessage: "This password appeared in a data breach, please choose another one.",
		// only the tests point this at a fake range API
		APIURL: apiURL,
	})
	// Step 3: set goauth up with the plugin
	app, err := exkit.New(context.Background(), exkit.Options{
		DB:      db,
		Plugins: []plugin.Plugin{hibpPlugin},
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
		dbPath = "haveibeenpwned_example.db"
	}
	app, err := newApp(dbPath, "")
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
