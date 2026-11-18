// Package siweclient runs the official better-auth client (siweClient) against goauth, with messages signed
// in node by a secp256k1 wallet.
package siweclient

import (
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins/siwe"
	siweconfig "github.com/better-go-auth/goauth/src/plugins/siwe/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

func TestOfficialClientSiwe(t *testing.T) {
	// Step 1: goauth with the siwe plugin and its default EIP-191 verifier (domain = BaseURL host)
	s := compattest.NewServer(t,
		compattest.WithPlugin(siwe.New(siweconfig.SIWEConfig{})),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = "http://localhost:3000"
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	// Step 2: run the official client script
	compattest.RunNodeClient(t, compattest.ClientDir("client"), "test-siwe.mjs", s.URL)
}
