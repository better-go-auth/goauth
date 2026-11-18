// Package oauthproxyclient runs the official better-auth client (src/tests/compat/client/test-oauth-proxy.mjs)
// against two goauth deployments with the oauth-proxy plugin: a production deployment (the only redirect URI
// registered at the fake OAuth provider) and a preview deployment proxying its OAuth callbacks through it.
package oauthproxyclient

import (
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	oauthproxy "github.com/better-go-auth/goauth/src/plugins/oauth-proxy"
	proxyconfig "github.com/better-go-auth/goauth/src/plugins/oauth-proxy/config"
	"github.com/better-go-auth/goauth/src/plugins/social"
	socialconfig "github.com/better-go-auth/goauth/src/plugins/social/config"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

// productionBase is production's BaseURL (and the preview's ProductionURL): the provider redirects there,
// and the fake provider rewrites it to the real production test server.
const productionBase = "http://localhost:3000"

func TestOfficialClientOAuthProxy(t *testing.T) {
	// Step 1: the fake provider
	fake := socialtest.New("client-id", "client-secret")
	t.Cleanup(fake.Close)
	newSocial := func() *social.Plugin {
		return social.New(socialconfig.SocialConfig{Providers: []providers.Provider{providers.Generic(providers.GenericOptions{
			ProviderID: "fake",
			Issuer:     fake.Issuer,
			ProviderOptions: providers.ProviderOptions{
				ClientID: fake.ClientID, ClientSecret: fake.ClientSecret,
				AuthorizationEndpoint: fake.AuthorizationEndpoint(), TokenEndpoint: fake.TokenEndpoint(),
				UserInfoEndpoint: fake.UserInfoEndpoint(), JWKSEndpoint: fake.JWKSEndpoint(),
			},
		})}})
	}
	trust := func(c *config.AuthConfig) {
		c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
	}

	// Step 2: production (BaseURL = productionBase) with the proxy plugin
	prodSocial := newSocial()
	production := compattest.NewServer(t,
		compattest.WithPlugin(prodSocial),
		compattest.WithPlugin(oauthproxy.New(proxyconfig.OAuthProxyConfig{}, oauthproxy.WithSocial(prodSocial))),
		compattest.WithConfig(func(c *config.AuthConfig) { c.BaseURL = productionBase; trust(c) }))
	fake.SetRedirectBase(production.URL)

	// Step 3: the preview deployment proxying through production
	prevSocial := newSocial()
	preview := compattest.NewServer(t,
		compattest.WithPlugin(prevSocial),
		compattest.WithPlugin(oauthproxy.New(proxyconfig.OAuthProxyConfig{ProductionURL: productionBase}, oauthproxy.WithSocial(prevSocial))),
		compattest.WithConfig(trust))

	// Step 4: run the official client against the preview
	compattest.RunNodeClient(t, compattest.ClientDir("client"), "test-oauth-proxy.mjs", preview.URL,
		"GOAUTH_PRODUCTION_BASE="+productionBase,
		"GOAUTH_PRODUCTION_URL="+production.URL,
		"GOAUTH_SECRET="+compattest.TestSecret,
	)
}
