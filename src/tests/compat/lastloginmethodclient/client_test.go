// Package lastloginmethodclient runs the official better-auth client (lastLoginMethodClient) against goauth's
// last-login-method plugin.
package lastloginmethodclient

import (
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	lastloginmethod "github.com/better-go-auth/goauth/src/plugins/last-login-method"
	llmconfig "github.com/better-go-auth/goauth/src/plugins/last-login-method/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

func TestOfficialClientLastLoginMethod(t *testing.T) {
	// Step 1: goauth with the plugin (better-auth defaults)
	s := compattest.NewServer(t,
		compattest.WithPlugin(lastloginmethod.New(llmconfig.LastLoginMethodConfig{})),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = "http://localhost:3000"
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	// Step 2: run the official client script
	compattest.RunNodeClient(t, compattest.ClientDir("client"), "test-last-login-method.mjs", s.URL)
}
