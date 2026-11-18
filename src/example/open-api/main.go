// Command open-api runs goauth with the open-api plugin: GET /api/auth/open-api/generate-schema returns the
// OpenAPI document of the auth routes (better-auth's format) and /api/auth/reference shows it in Scalar.
//
//	go run ./src/example/open-api     # open http://localhost:8080/api/auth/reference
//	go test ./src/example/open-api    # checks the document and the page
package main

import (
	"context"
	"log"
	"os"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	openapi "github.com/better-go-auth/goauth/src/plugins/open-api"
	openapiconfig "github.com/better-go-auth/goauth/src/plugins/open-api/config"
	"github.com/better-go-auth/goauth/src/plugins/username"
	usernameconfig "github.com/better-go-auth/goauth/src/plugins/username/config"
)

// newApp builds the example server. dbPath "" uses an in-memory database (tests).
func newApp(dbPath string) (*exkit.App, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, err
	}
	// Step 2: configure the plugin (zero values = better-auth defaults: page at /reference, theme "default")
	openAPIPlugin := openapi.New(openapiconfig.OpenAPIConfig{
		Theme: "purple",
	})
	// Step 3: set goauth up with the plugin and one more plugin whose routes and user fields get documented
	app, err := exkit.New(context.Background(), exkit.Options{
		DB:      db,
		Plugins: []plugin.Plugin{openAPIPlugin, username.New(usernameconfig.UsernameConfig{})},
	})
	if err != nil {
		return nil, err
	}
	// Step 4: a protected route of your own (not part of the auth document, it is outside /api/auth)
	app.AddMeRoute()
	return app, nil
}

func main() {
	dbPath := os.Getenv("SQLITE_DB")
	if dbPath == "" {
		dbPath = "open_api_example.db"
	}
	app, err := newApp(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
