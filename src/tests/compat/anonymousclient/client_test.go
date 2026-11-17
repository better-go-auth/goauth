// Package anonymousclient runs the official better-auth client (anonymousClient) against goauth.
package anonymousclient

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins/anonymous"
	anonconfig "github.com/better-go-auth/goauth/src/plugins/anonymous/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

func TestOfficialClientAnonymous(t *testing.T) {
	// Step 1: record what onLinkAccount receives
	var mu sync.Mutex
	links := 0
	var lastAnon, lastNew string
	onLink := func(_ context.Context, d anonconfig.LinkAccountData) error {
		mu.Lock()
		defer mu.Unlock()
		links++
		lastAnon, lastNew = d.AnonymousUser.User.ID, d.NewUser.User.ID
		return nil
	}

	// Step 2: start goauth with the anonymous plugin
	s := compattest.NewServer(t,
		compattest.WithPlugin(anonymous.New(anonconfig.AnonymousConfig{OnLinkAccount: onLink})),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = "http://localhost:3000"
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	// Step 3: test-only endpoint the script reads the link calls and user existence from (?user=<id>)
	s.Mux.HandleFunc("/test/anonymous-state", func(w http.ResponseWriter, r *http.Request) {
		u, err := s.Auth.Repositories().FindUserByID(r.Context(), r.URL.Query().Get("user"))
		mu.Lock()
		state := map[string]any{
			"links":               links,
			"lastAnonymousUserId": lastAnon,
			"lastNewUserId":       lastNew,
			"userExists":          err == nil && u != nil,
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(state)
	})

	// Step 4: run the official client script
	compattest.RunNodeClient(t, compattest.ClientDir("client"), "test-anonymous.mjs", s.URL)
}
