// Package oidcproviderclient runs the official better-auth client with oidcClient()
// (src/tests/compat/client/test-oidc-provider.mjs) against goauth's oidc-provider, with HS256 id_tokens and
// with the jwt plugin (JWKS), and signs in to a goauth relying party (generic-oauth) with a goauth
// identity provider (rp_test.go).
package oidcproviderclient

import (
	"testing"

	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/jwt"
	jwtconfig "github.com/better-go-auth/goauth/src/plugins/jwt/config"
	oidcprovider "github.com/better-go-auth/goauth/src/plugins/oidc-provider"
	oidcconfig "github.com/better-go-auth/goauth/src/plugins/oidc-provider/config"
	"github.com/better-go-auth/goauth/src/plugins/oidc-provider/oidctest"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

func TestOfficialClientOIDCProvider(t *testing.T) {
	for _, mode := range []string{"hs256", "jwt"} {
		t.Run(mode, func(t *testing.T) {
			// Step 1: goauth with the oidc-provider (and the jwt plugin for jwt-signed id_tokens)
			var ps []plugin.Plugin
			if mode == "jwt" {
				ps = append(ps, jwt.New(jwtconfig.JWTConfig{Jwks: jwtconfig.JwksConfig{KeyPairConfig: jwtconfig.KeyPairConfig{Alg: jwtconfig.AlgRS256}}}))
			}
			ps = append(ps, oidcprovider.New(oidcconfig.Config{LoginPage: "/login", ConsentPage: "/consent", UseJWTPlugin: mode == "jwt"}))
			srv := oidctest.NewServer(t, oidctest.Options{Plugins: ps})
			// Step 2: the official client script
			compattest.RunNodeClient(t, compattest.ClientDir("client"), "test-oidc-provider.mjs", srv.URL, "GOAUTH_OIDC_MODE="+mode)
		})
	}
}
