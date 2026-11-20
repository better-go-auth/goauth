// Package scimclient runs the official @better-auth/scim client (src/tests/compat/client-scim/test-scim.mjs)
// against goauth's scim plugin.
package scimclient

import (
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins/scim"
	scimconfig "github.com/better-go-auth/goauth/src/plugins/scim/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

func TestOfficialSCIMClient(t *testing.T) {
	// Step 1: goauth with the scim plugin
	s := compattest.NewServer(t,
		compattest.WithPlugin(scim.New(scimconfig.SCIMConfig{})),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*")
		}))
	// Step 2: run the official client
	compattest.RunNodeClient(t, compattest.ClientDir("client-scim"), "test-scim.mjs", s.URL)
}
