// Command scim runs goauth with the scim plugin (SCIM 2.0 user provisioning) and the organization plugin: an
// organization admin generates a SCIM token, and the identity provider provisions users into the organization
// through /api/auth/scim/v2/Users.
//
//	go run ./src/example/scim     # http://localhost:8080/docs
//	go test ./src/example/scim    # generates a token and provisions, updates and deprovisions a user
package main

import (
	"context"
	"log"
	"os"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/org"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	"github.com/better-go-auth/goauth/src/plugins/scim"
	scimconfig "github.com/better-go-auth/goauth/src/plugins/scim/config"
)

// newApp builds the example server. dbPath "" uses an in-memory database (tests).
func newApp(dbPath string) (*exkit.App, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, err
	}
	// Step 2: the organization plugin (SCIM tokens scoped to an organization)
	orgPlugin, err := org.NewWithGorm(db, orgconfig.OrgConfig{})
	if err != nil {
		return nil, err
	}
	// Step 3: the scim plugin: tokens stored hashed, connections owned by the user who created them
	scimPlugin := scim.New(scimconfig.SCIMConfig{
		ProviderOwnership: true,
		StoreSCIMToken:    scimconfig.TokenStorage{Mode: scimconfig.StoreHashed},
	})
	// Step 4: set goauth up with both plugins
	app, err := exkit.New(context.Background(), exkit.Options{DB: db, Plugins: []plugin.Plugin{orgPlugin, scimPlugin}})
	if err != nil {
		return nil, err
	}
	app.AddMeRoute()
	return app, nil
}

func main() {
	dbPath := os.Getenv("SQLITE_DB")
	if dbPath == "" {
		dbPath = "scim_example.db"
	}
	app, err := newApp(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
