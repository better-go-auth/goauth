// Command passkey runs goauth with the passkey (WebAuthn) plugin: a signed-in user registers a passkey
// (Touch ID, Windows Hello, a security key, a phone) and later signs in with it instead of a password.
//
//	go run ./src/example/passkey             # http://localhost:8080/docs
//	go test ./src/example/passkey            # runs the flow end to end with a software authenticator
package main

import (
	"context"
	"log"
	"os"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/passkey"
	pkconfig "github.com/better-go-auth/goauth/src/plugins/passkey/config"
)

// newApp builds the example server. dbPath "" uses an in-memory database (tests).
func newApp(dbPath string) (*exkit.App, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, err
	}
	// Step 2: configure the plugin. RPID is the domain passkeys are bound to (default: the host of
	// BaseURL), RPName is shown by the authenticator (default: AppName), Origin is the page origin the
	// browser reports (default: the request's Origin header). Set all three in production.
	passkeyPlugin := passkey.New(pkconfig.PasskeyConfig{
		RPID:   "localhost",
		RPName: "GoAuth Example",
		Origin: []string{exkit.DefaultBaseURL},
	})
	// Step 3: set goauth up with the plugin
	app, err := exkit.New(context.Background(), exkit.Options{
		DB:      db,
		Plugins: []plugin.Plugin{passkeyPlugin},
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
		dbPath = "passkey_example.db"
	}
	app, err := newApp(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
