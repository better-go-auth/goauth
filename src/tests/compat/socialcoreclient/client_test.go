// Package socialcoreclient runs the official better-auth client (src/tests/compat/client/test-social.mjs) against
// goauth configured like `betterAuth({ socialProviders, account: { storeAccountCookie, encryptOAuthTokens } })`:
// the providers live in AuthConfig.SocialProviders and no social plugin is passed.
package socialcoreclient

import (
	"testing"

	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins/social"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

const appBase = "http://localhost:3000"

func TestOfficialClientSocialProvidersInCore(t *testing.T) {
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

	// Step 2: goauth with socialProviders in the core config (no social plugin) and the account cookie
	s := compattest.NewServer(t, compattest.WithConfig(func(c *config.AuthConfig) {
		c.BaseURL = appBase
		c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		c.SocialProviders = []providers.Provider{generic("fake"), generic("fake2")}
		c.Account.StoreAccountCookie = true
		c.Account.EncryptOAuthTokens = true
	}))
	if _, ok := goauth.GetPlugin[*social.Plugin](s.Auth, social.PluginID); !ok {
		t.Fatal("SocialProviders must install the social plugin")
	}
	fake.SetRedirectBase(s.URL)

	// Step 3: an id_token for a second user
	idEmail := "id.token.user@example.com"
	idToken := fake.SignIDToken(socialtest.Profile{Sub: "id-user", Email: idEmail, EmailVerified: true, Name: "Id User"}, "", nil)

	// Step 4: run the official client
	compattest.RunNodeClient(t, compattest.ClientDir("client"), "test-social.mjs", s.URL,
		"GOAUTH_APP_BASE="+appBase,
		"GOAUTH_ID_TOKEN="+idToken,
		"GOAUTH_ID_EMAIL="+idEmail,
		"GOAUTH_ACCOUNT_COOKIE=1",
	)
}
