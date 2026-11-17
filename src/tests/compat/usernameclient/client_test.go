// Package usernameclient runs the official better-auth client (usernameClient) against goauth.
package usernameclient

import (
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins/username"
	usernameconfig "github.com/better-go-auth/goauth/src/plugins/username/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

func TestOfficialClientUsername(t *testing.T) {
	// Step 1: start goauth with the username plugin (better-auth defaults)
	s := compattest.NewServer(t,
		compattest.WithPlugin(username.New(usernameconfig.UsernameConfig{})),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = "http://localhost:3000"
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	// Step 2: run the official client script
	compattest.RunNodeClient(t, compattest.ClientDir("client"), "test-username.mjs", s.URL)
}
