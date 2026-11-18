// Command generic-oauth runs goauth with the generic-oauth plugin: users sign in with any OAuth 2.0 /
// OpenID Connect provider (Keycloak, Okta, Auth0, your own IdP, ...) through POST /api/auth/sign-in/oauth2,
// and signed-in users link a provider account with POST /api/auth/oauth2/link.
//
//	OAUTH_DISCOVERY_URL=https://idp.example.com/.well-known/openid-configuration \
//	OAUTH_CLIENT_ID=... OAUTH_CLIENT_SECRET=... go run ./src/example/generic-oauth   # http://localhost:8080/docs
//	go test ./src/example/generic-oauth     # the flow end to end, against an in-process fake provider
//
// Register http://localhost:8080/api/auth/oauth2/callback/my-idp as the redirect URI at the provider.
package main

import (
	"context"
	"log"
	"os"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	genericoauth "github.com/better-go-auth/goauth/src/plugins/generic-oauth"
	goconfig "github.com/better-go-auth/goauth/src/plugins/generic-oauth/config"
)

// newApp builds the example server with the given providers. dbPath "" uses an in-memory database (tests).
func newApp(dbPath string, providers ...goconfig.ProviderConfig) (*exkit.App, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, err
	}
	// Step 2: configure the plugin (zero values = better-auth defaults: linking on, OAuth state in the
	// database, discovery documents cached for 10 minutes)
	oauthPlugin := genericoauth.New(goconfig.Config{
		Providers: providers,
		// store the provider's access/refresh tokens encrypted with the auth secret
		EncryptOAuthTokens: true,
	})
	// Step 3: set goauth up with the plugin
	app, err := exkit.New(context.Background(), exkit.Options{
		DB:      db,
		Plugins: []plugin.Plugin{oauthPlugin},
	})
	if err != nil {
		return nil, err
	}
	// Step 4: a protected route of your own
	app.AddMeRoute()
	return app, nil
}

// providerFromEnv is an OpenID Connect provider "my-idp" configured from its discovery document.
func providerFromEnv() goconfig.ProviderConfig {
	return goconfig.ProviderConfig{
		ProviderID:   "my-idp",
		DiscoveryURL: os.Getenv("OAUTH_DISCOVERY_URL"),
		ClientID:     os.Getenv("OAUTH_CLIENT_ID"),
		ClientSecret: os.Getenv("OAUTH_CLIENT_SECRET"),
		Scopes:       []string{"openid", "email", "profile"},
		PKCE:         true,
	}
}

func main() {
	// Step 1: the provider settings
	if os.Getenv("OAUTH_DISCOVERY_URL") == "" || os.Getenv("OAUTH_CLIENT_ID") == "" {
		log.Println("OAUTH_DISCOVERY_URL / OAUTH_CLIENT_ID are not set: sign-in answers INVALID_OAUTH_CONFIGURATION")
	}
	// Step 2: the server
	dbPath := os.Getenv("SQLITE_DB")
	if dbPath == "" {
		dbPath = "generic_oauth_example.db"
	}
	app, err := newApp(dbPath, providerFromEnv())
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
