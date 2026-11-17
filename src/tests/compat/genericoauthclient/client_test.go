// Package genericoauthclient runs the official better-auth client with genericOAuthClient()
// (src/tests/compat/client/test-generic-oauth.mjs) against goauth with the generic-oauth plugin pointed at an
// in-process fake OAuth2/OIDC provider.
package genericoauthclient

import (
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	genericoauth "github.com/better-go-auth/goauth/src/plugins/generic-oauth"
	goconfig "github.com/better-go-auth/goauth/src/plugins/generic-oauth/config"
	socialproviders "github.com/better-go-auth/goauth/src/plugins/social/providers"
	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

const appBase = "http://localhost:3000"

func TestOfficialClientGenericOAuth(t *testing.T) {
	// Step 1: the fake provider
	fake := socialtest.New("client-id", "client-secret")
	t.Cleanup(fake.Close)

	// Step 2: "fake" with explicit endpoints (PKCE, HTTP Basic client auth) and "disc" via OIDC discovery
	providers := []goconfig.ProviderConfig{
		{
			ProviderID:       "fake",
			AuthorizationURL: fake.AuthorizationEndpoint(),
			TokenURL:         fake.TokenEndpoint(),
			UserInfoURL:      fake.UserInfoEndpoint(),
			ClientID:         fake.ClientID,
			ClientSecret:     fake.ClientSecret,
			Scopes:           []string{"openid", "email", "profile"},
			PKCE:             true,
			Authentication:   socialproviders.AuthBasic,
		},
		{
			ProviderID:   "disc",
			DiscoveryURL: fake.DiscoveryURL(),
			ClientID:     fake.ClientID,
			ClientSecret: fake.ClientSecret,
			Scopes:       []string{"openid", "email", "profile"},
			PKCE:         true,
		},
	}

	// Step 3: goauth with the generic-oauth plugin
	s := compattest.NewServer(t,
		compattest.WithPlugin(genericoauth.New(goconfig.Config{Providers: providers})),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = appBase
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}))
	// the app's BaseURL is not the test server: the provider redirects to the real server instead
	fake.SetRedirectBase(s.URL)

	// Step 4: run the official client
	compattest.RunNodeClient(t, compattest.ClientDir("client"), "test-generic-oauth.mjs", s.URL,
		"GOAUTH_APP_BASE="+appBase,
		"GOAUTH_PROVIDER_EMAIL=fake.user@example.com",
	)
}
