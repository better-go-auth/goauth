// Command last-login-method runs goauth with the last-login-method plugin: every successful sign-in sets the
// `better-auth.last_used_login_method` cookie (readable by JavaScript) to the method used, so a login page
// can highlight "Last used" next to the right button.
//
//	go run ./src/example/last-login-method    # http://localhost:8080/docs
//	go test ./src/example/last-login-method   # the flow end to end
package main

import (
	"context"
	"log"
	"os"

	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	lastloginmethod "github.com/better-go-auth/goauth/src/plugins/last-login-method"
	llmconfig "github.com/better-go-auth/goauth/src/plugins/last-login-method/config"
	"github.com/better-go-auth/goauth/src/plugins/username"
	usernameconfig "github.com/better-go-auth/goauth/src/plugins/username/config"
)

// resolveUsername reports "username" for username sign-ins, which better-auth's default rules do not know;
// every other request uses the default rules.
func resolveUsername(c *endpointhooks.Context) (string, bool) {
	if c.Path == "/sign-in/username" {
		return "username", true
	}
	return "", false
}

// newApp builds the example server. dbPath "" uses an in-memory database (tests).
func newApp(dbPath string) (*exkit.App, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, err
	}
	// Step 2: configure the plugin (cookie only; StoreInDatabase also writes user.lastLoginMethod)
	lastLogin := lastloginmethod.New(llmconfig.LastLoginMethodConfig{
		CustomResolveMethod: resolveUsername,
	})
	// Step 3: set goauth up with the plugins
	app, err := exkit.New(context.Background(), exkit.Options{
		DB:      db,
		Plugins: []plugin.Plugin{username.New(usernameconfig.UsernameConfig{}), lastLogin},
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
		dbPath = "last_login_method_example.db"
	}
	app, err := newApp(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
