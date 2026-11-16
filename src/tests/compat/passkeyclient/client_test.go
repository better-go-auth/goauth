// Package passkeyclient runs the official @better-auth/passkey client against goauth's passkey plugin.
package passkeyclient

import (
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins/passkey"
	pkconfig "github.com/better-go-auth/goauth/src/plugins/passkey/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

// pageOrigin is the origin the Node "browser" claims (Origin header and clientDataJSON origin).
const pageOrigin = "http://localhost:3000"

func TestOfficialPasskeyClient(t *testing.T) {
	// Step 1: BaseURL on localhost makes rpID "localhost"; the page origin is trusted for the origin check
	s := compattest.NewServer(t,
		compattest.WithPlugin(passkey.New(pkconfig.PasskeyConfig{})),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = pageOrigin
			c.TrustedOrigins = append(c.TrustedOrigins, pageOrigin, "http://127.0.0.1:*")
		}),
	)
	// Step 2: run the client script against the in-process server
	compattest.RunNodeClient(t, compattest.ClientDir("client-passkey"), "test-passkey.mjs", s.URL, "PASSKEY_ORIGIN="+pageOrigin)
}
