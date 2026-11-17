package test

import (
	"net/http"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	multisession "github.com/better-go-auth/goauth/src/plugins/multi-session"
	msconfig "github.com/better-go-auth/goauth/src/plugins/multi-session/config"
	"github.com/better-go-auth/goauth/src/plugins/username"
	usernameconfig "github.com/better-go-auth/goauth/src/plugins/username/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

// TestMultiSessionCoversPluginsListedBefore checks that a sign-in route of a plugin listed BEFORE multi-session
// (here /sign-in/username) still gets the multi-session cookie: goauth.New initializes multi-session first.
func TestMultiSessionCoversPluginsListedBefore(t *testing.T) {
	// Step 1: username is listed before multi-session
	s := compattest.NewServer(t,
		compattest.WithPlugin(username.New(usernameconfig.UsernameConfig{})),
		compattest.WithPlugin(multisession.New(msconfig.MultiSessionConfig{})),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = "http://localhost:3000"
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)
	s.Client.Jar = nil
	e := &env{Server: s}

	// Step 2: sign up with a username, then sign in on a fresh device through the username plugin
	r := e.do(t, newBrowser(), http.MethodPost, "/api/auth/sign-up/email",
		map[string]any{"email": "order@example.com", "password": password, "name": "Order", "username": "orderuser"})
	expectStatus(t, r, http.StatusOK)
	b := newBrowser()
	r = e.do(t, b, http.MethodPost, "/api/auth/sign-in/username", map[string]any{"username": "orderuser", "password": password})
	expectStatus(t, r, http.StatusOK)

	// Step 3: the multi-session after hook wrapped the username route
	if got := b.multiCount(); got != 1 {
		t.Fatalf("multi-session cookies after /sign-in/username = %d, want 1", got)
	}
}
