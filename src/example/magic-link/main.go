// Command magic-link runs goauth with the magic-link plugin: users get a one-time sign-in link by email.
// Opening the link (GET /api/auth/magic-link/verify) signs them in, and signs them up on first use.
//
//	go run ./src/example/magic-link           # http://localhost:8080/docs (links are printed to the log)
//	go test ./src/example/magic-link          # runs the flow end to end
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	magiclink "github.com/better-go-auth/goauth/src/plugins/magic-link"
	magiclinkconfig "github.com/better-go-auth/goauth/src/plugins/magic-link/config"
)

// newApp builds the example server. dbPath "" uses an in-memory database (tests). The outbox holds the
// links the plugin "emailed" (kind "magic-link").
func newApp(dbPath string) (*exkit.App, *exkit.Outbox, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, nil, err
	}
	// Step 2: the email sender. A real app emails data.URL; the example records it in the outbox
	outbox := &exkit.Outbox{}
	send := func(data magiclinkconfig.SendMagicLinkData, _ *http.Request) error {
		outbox.Put("magic-link", data.Email, data.URL)
		return nil
	}
	// Step 3: configure the plugin (zero values = better-auth defaults: 5 minute links, plain token storage)
	linkPlugin := magiclink.New(magiclinkconfig.MagicLinkConfig{
		SendMagicLink: send,
		ExpiresIn:     10 * time.Minute,
		// store only a SHA-256 of the token, so a leaked database can't be used to sign in
		StoreToken: magiclinkconfig.StoreTokenConfig{Mode: magiclinkconfig.StoreTokenHashed},
	})
	// Step 4: set goauth up with the plugin
	app, err := exkit.New(context.Background(), exkit.Options{
		DB:      db,
		Plugins: []plugin.Plugin{linkPlugin},
	})
	if err != nil {
		return nil, nil, err
	}
	// Step 5: a protected route of your own
	app.AddMeRoute()
	return app, outbox, nil
}

func main() {
	dbPath := os.Getenv("SQLITE_DB")
	if dbPath == "" {
		dbPath = "magic_link_example.db"
	}
	app, _, err := newApp(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
