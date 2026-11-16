// Package socialclient runs the official better-auth client (src/tests/compat/client/test-social.mjs) against
// goauth with the social plugin pointed at an in-process fake OAuth2/OIDC provider.
package socialclient

import (
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins/social"
	socialconfig "github.com/better-go-auth/goauth/src/plugins/social/config"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

const appBase = "http://localhost:3000"

func TestOfficialClientSocial(t *testing.T) {
	// Step 1: the fake provider
	fake := socialtest.New("client-id", "client-secret")
	t.Cleanup(fake.Close)
	generic := func(id string) providers.Provider {
		return providers.Generic(providers.GenericOptions{
			ProviderID: id,
			Issuer:     fake.Issuer,
			ProviderOptions: providers.ProviderOptions{
				ClientID:              fake.ClientID,
				ClientSecret:          fake.ClientSecret,
				AuthorizationEndpoint: fake.AuthorizationEndpoint(),
				TokenEndpoint:         fake.TokenEndpoint(),
				UserInfoEndpoint:      fake.UserInfoEndpoint(),
				JWKSEndpoint:          fake.JWKSEndpoint(),
			},
		})
	}

	// Step 2: goauth with the social plugin ("fake" for sign-in, "fake2" for linking)
	s := compattest.NewServer(t,
		compattest.WithPlugin(social.New(socialconfig.SocialConfig{Providers: []providers.Provider{generic("fake"), generic("fake2")}})),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = appBase
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}))
	// the app's BaseURL is not the test server: the provider redirects to the real server instead
	fake.SetRedirectBase(s.URL)

	// Step 3: an id_token for a second user
	idEmail := "id.token.user@example.com"
	idToken := fake.SignIDToken(socialtest.Profile{Sub: "id-user", Email: idEmail, EmailVerified: true, Name: "Id User"}, "", nil)

	// Step 4: run the official client
	compattest.RunNodeClient(t, compattest.ClientDir("client"), "test-social.mjs", s.URL,
		"GOAUTH_APP_BASE="+appBase,
		"GOAUTH_ID_TOKEN="+idToken,
		"GOAUTH_ID_EMAIL="+idEmail,
	)
}
