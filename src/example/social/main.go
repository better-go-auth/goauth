// Command social runs goauth with the social plugin: users sign in with an OAuth provider (GitHub here)
// through POST /api/auth/sign-in/social, and signed-in users link more providers with POST /api/auth/link-social.
//
//	GITHUB_CLIENT_ID=... GITHUB_CLIENT_SECRET=... go run ./src/example/social   # http://localhost:8080/docs
//	go test ./src/example/social     # the flow end to end, against an in-process fake provider
//
// Register the GitHub OAuth app with the callback URL http://localhost:8080/api/auth/callback/github.
package main

import (
	"context"
	"log"
	"os"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/social"
	socialconfig "github.com/better-go-auth/goauth/src/plugins/social/config"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
)

// newApp builds the example server with the given providers. dbPath "" uses an in-memory database (tests).
func newApp(dbPath string, socialProviders ...providers.Provider) (*exkit.App, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, err
	}
	// Step 2: configure the plugin: the providers plus the account linking policy (zero values =
	// better-auth defaults: linking on, implicit linking by verified email, OAuth state in the database)
	socialPlugin := social.New(socialconfig.SocialConfig{
		Providers: socialProviders,
		AccountLinking: socialconfig.AccountLinking{
			// providers whose accounts may be linked even when they report an unverified email
			TrustedProviders: []string{"github"},
		},
		// store the provider's access/refresh tokens encrypted with the auth secret
		EncryptOAuthTokens: true,
	})
	// Step 3: set goauth up with the plugin
	app, err := exkit.New(context.Background(), exkit.Options{
		DB:      db,
		Plugins: []plugin.Plugin{socialPlugin},
	})
	if err != nil {
		return nil, err
	}
	// Step 4: a protected route of your own
	app.AddMeRoute()
	return app, nil
}

// githubFromEnv is the GitHub provider with the OAuth app credentials from the environment.
func githubFromEnv() providers.Provider {
	return providers.GitHub(providers.GitHubOptions{ProviderOptions: providers.ProviderOptions{
		ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
	}})
}

func main() {
	// Step 1: the provider credentials
	if os.Getenv("GITHUB_CLIENT_ID") == "" || os.Getenv("GITHUB_CLIENT_SECRET") == "" {
		log.Println("GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET are not set: GitHub will refuse the sign-in")
	}
	// Step 2: the server
	dbPath := os.Getenv("SQLITE_DB")
	if dbPath == "" {
		dbPath = "social_example.db"
	}
	app, err := newApp(dbPath, githubFromEnv())
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
