// Package ratelimitclient runs the official better-auth client against goauth's global rate limiter.
package ratelimitclient

import (
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/providers/ratelimit"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

func TestOfficialClientRateLimit(t *testing.T) {
	// Step 1: goauth with the limiter on (better-auth enables it in production only) and a custom rule
	s := compattest.NewServer(t,
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = "http://localhost:3000"
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
			c.RateLimit.Enabled = new(true)
			c.RateLimit.CustomRules = map[string]ratelimit.CustomRule{"/get-session": {Window: time.Minute, Max: 2}}
		}),
	)

	// Step 2: run the official client script
	compattest.RunNodeClient(t, compattest.ClientDir("client"), "test-rate-limit.mjs", s.URL)
}
