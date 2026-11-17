// Package multisessionclient runs the official better-auth client (multiSessionClient) against goauth.
package multisessionclient

import (
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	multisession "github.com/better-go-auth/goauth/src/plugins/multi-session"
	msconfig "github.com/better-go-auth/goauth/src/plugins/multi-session/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

func newServer(t *testing.T, cfg msconfig.MultiSessionConfig) *compattest.Server {
	t.Helper()
	return compattest.NewServer(t,
		compattest.WithPlugin(multisession.New(cfg)),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = "http://localhost:3000"
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)
}

func TestOfficialClientMultiSession(t *testing.T) {
	// Step 1: one server with the default maximum (5) and one limited to 2 sessions per device
	s := newServer(t, msconfig.MultiSessionConfig{})
	limited := newServer(t, msconfig.MultiSessionConfig{MaximumSessions: 2})

	// Step 2: run the official client script against both
	compattest.RunNodeClient(t, compattest.ClientDir("client"), "test-multi-session.mjs", s.URL,
		"GOAUTH_URL_MAX2="+limited.URL)
}
