// Command sso runs goauth with the sso plugin (enterprise OIDC / SAML single sign-on) and the organization
// plugin: providers registered for an organization add their users to it.
//
//	go run ./src/example/sso      # http://localhost:8080/docs
//	go test ./src/example/sso     # registers an OIDC provider and signs a user in through a fake IdP
//
// To try it with a real OIDC identity provider, set SSO_ISSUER, SSO_CLIENT_ID, SSO_CLIENT_SECRET and
// SSO_DOMAIN: the provider "default" is then configured in code (defaultSSO) and
// POST /api/auth/sign-in/sso {"email": "you@<SSO_DOMAIN>", "callbackURL": "/"} starts the sign-in.
package main

import (
	"context"
	"log"
	"os"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/org"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	"github.com/better-go-auth/goauth/src/plugins/sso"
	ssoconfig "github.com/better-go-auth/goauth/src/plugins/sso/config"
)

// appOptions configure the example.
type appOptions struct {
	// DBPath "" uses an in-memory database (tests).
	DBPath string
	// DefaultSSO are providers configured in code.
	DefaultSSO []ssoconfig.DefaultProvider
	// TrustedOrigins are extra trusted origins (an IdP on a private network must be trusted).
	TrustedOrigins []string
}

// newApp builds the example server.
func newApp(o appOptions) (*exkit.App, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(o.DBPath)
	if err != nil {
		return nil, err
	}
	// Step 2: the organization plugin (organization providers and provisioning)
	orgPlugin, err := org.NewWithGorm(db, orgconfig.OrgConfig{})
	if err != nil {
		return nil, err
	}
	// Step 3: the sso plugin: SSO users join the provider's organization as "member"
	ssoPlugin := sso.New(ssoconfig.SSOConfig{
		DefaultSSO:               o.DefaultSSO,
		OrganizationProvisioning: &ssoconfig.OrganizationProvisioning{DefaultRole: "member"},
	})
	// Step 4: set goauth up with both plugins
	app, err := exkit.New(context.Background(), exkit.Options{
		DB:      db,
		Plugins: []plugin.Plugin{orgPlugin, ssoPlugin},
		Configure: func(c *config.AuthConfig) {
			c.TrustedOrigins = append(c.TrustedOrigins, o.TrustedOrigins...)
		},
	})
	if err != nil {
		return nil, err
	}
	// Step 5: a protected route of your own
	app.AddMeRoute()
	return app, nil
}

func main() {
	// Step 1: the database file
	o := appOptions{DBPath: os.Getenv("SQLITE_DB")}
	if o.DBPath == "" {
		o.DBPath = "sso_example.db"
	}
	// Step 2: an OIDC provider from the environment (discovered at sign-in)
	if issuer := os.Getenv("SSO_ISSUER"); issuer != "" {
		pkce := true
		o.DefaultSSO = []ssoconfig.DefaultProvider{{
			ProviderID: "default",
			Domain:     os.Getenv("SSO_DOMAIN"),
			OIDCConfig: &ssoconfig.OIDCConfig{
				Issuer: issuer, ClientID: os.Getenv("SSO_CLIENT_ID"), ClientSecret: os.Getenv("SSO_CLIENT_SECRET"), PKCE: &pkce,
			},
		}}
		o.TrustedOrigins = append(o.TrustedOrigins, issuer)
	}
	app, err := newApp(o)
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
