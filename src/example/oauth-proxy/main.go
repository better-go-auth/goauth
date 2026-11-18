// Command oauth-proxy runs goauth with the social and oauth-proxy plugins. Run the same binary as the
// production deployment (the only callback URL registered at the OAuth provider) and as any number of
// preview deployments: previews send the provider's callback to production, which hands the signed-in
// profile back, encrypted, to the preview's GET /api/auth/oauth-proxy-callback.
//
//	# production, registered at GitHub with http://localhost:8080/api/auth/callback/github
//	GITHUB_CLIENT_ID=... GITHUB_CLIENT_SECRET=... go run ./src/example/oauth-proxy
//	# a preview on another port, proxying through production
//	PORT=8081 BASE_URL=http://localhost:8081 PRODUCTION_URL=http://localhost:8080 SQLITE_DB=preview.db \
//	  GITHUB_CLIENT_ID=... GITHUB_CLIENT_SECRET=... go run ./src/example/oauth-proxy
//	go test ./src/example/oauth-proxy   # the whole preview flow against an in-process fake provider
//
// Both deployments must share the auth secret (exkit.Secret here, BETTER_AUTH_SECRET in real apps).
package main

import (
	"context"
	"log"
	"os"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	oauthproxy "github.com/better-go-auth/goauth/src/plugins/oauth-proxy"
	proxyconfig "github.com/better-go-auth/goauth/src/plugins/oauth-proxy/config"
	"github.com/better-go-auth/goauth/src/plugins/social"
	socialconfig "github.com/better-go-auth/goauth/src/plugins/social/config"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
)

// newApp builds one deployment. baseURL is its own public URL, productionURL the production deployment's
// URL ("" or the same origin = this is production). dbPath "" uses an in-memory database (tests).
func newApp(dbPath, baseURL, productionURL string, socialProviders ...providers.Provider) (*exkit.App, error) {
	// Step 1: open the database (each deployment has its own)
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, err
	}
	// Step 2: the social plugin with the providers
	socialPlugin := social.New(socialconfig.SocialConfig{Providers: socialProviders})
	// Step 3: the proxy: ProductionURL decides whether this deployment proxies its callbacks
	proxy := oauthproxy.New(proxyconfig.OAuthProxyConfig{ProductionURL: productionURL}, oauthproxy.WithSocial(socialPlugin))
	// Step 4: goauth with both plugins
	app, err := exkit.New(context.Background(), exkit.Options{
		DB:      db,
		BaseURL: baseURL,
		Plugins: []plugin.Plugin{socialPlugin, proxy},
	})
	if err != nil {
		return nil, err
	}
	// Step 5: a protected route of your own
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
	// Step 1: which deployment this is
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = exkit.DefaultBaseURL
	}
	productionURL := os.Getenv("PRODUCTION_URL")
	if productionURL == "" {
		productionURL = baseURL
	}
	dbPath := os.Getenv("SQLITE_DB")
	if dbPath == "" {
		dbPath = "oauth_proxy_example.db"
	}
	// Step 2: the server
	app, err := newApp(dbPath, baseURL, productionURL, githubFromEnv())
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("deployment %s, production %s", baseURL, productionURL)
	exkit.Serve(app.Mux)
}
