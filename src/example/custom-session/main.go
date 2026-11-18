// Command custom-session runs goauth with the custom-session plugin: GET /api/auth/get-session returns the
// session, the user and the user's roles computed by a Go callback.
//
//	go run ./src/example/custom-session    # http://localhost:8080/docs
//	go test ./src/example/custom-session   # the flow end to end
package main

import (
	"context"
	"log"
	"os"
	"strings"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	customsession "github.com/better-go-auth/goauth/src/plugins/custom-session"
	csconfig "github.com/better-go-auth/goauth/src/plugins/custom-session/config"
)

// customSession adds the user's roles and a display name to the session response. A real app would load
// the roles from its own tables.
func customSession(_ context.Context, s *csconfig.Session) (any, error) {
	// Step 1: compute the extra data
	roles := []string{"member"}
	if strings.HasSuffix(s.User.Email, "@example.com") {
		roles = append(roles, "staff")
	}
	// Step 2: return what the client receives instead of {session, user}
	return map[string]any{
		"session": s.Session,
		"user":    s.User,
		"roles":   roles,
		"display": strings.ToUpper(s.User.Name),
	}, nil
}

// newApp builds the example server. dbPath "" uses an in-memory database (tests).
func newApp(dbPath string) (*exkit.App, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, err
	}
	// Step 2: set goauth up with the plugin
	app, err := exkit.New(context.Background(), exkit.Options{
		DB:      db,
		Plugins: []plugin.Plugin{customsession.New(customSession)},
	})
	if err != nil {
		return nil, err
	}
	// Step 3: a protected route of your own
	app.AddMeRoute()
	return app, nil
}

func main() {
	dbPath := os.Getenv("SQLITE_DB")
	if dbPath == "" {
		dbPath = "custom_session_example.db"
	}
	app, err := newApp(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
