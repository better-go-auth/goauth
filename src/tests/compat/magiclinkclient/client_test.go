// Package magiclinkclient runs the official better-auth client's magic-link plugin against goauth.
package magiclinkclient

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	magiclink "github.com/better-go-auth/goauth/src/plugins/magic-link"
	mlconfig "github.com/better-go-auth/goauth/src/plugins/magic-link/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

func TestOfficialClientMagicLink(t *testing.T) {
	// Step 1: capture the links the plugin sends, keyed by lower-cased email
	var mu sync.Mutex
	links := map[string]mlconfig.SendMagicLinkData{}
	plugin := magiclink.New(mlconfig.MagicLinkConfig{
		SendMagicLink: func(data mlconfig.SendMagicLinkData, _ *http.Request) error {
			mu.Lock()
			defer mu.Unlock()
			links[strings.ToLower(data.Email)] = data
			return nil
		},
	})

	// Step 2: start goauth with the plugin and trusted local origins
	s := compattest.NewServer(t,
		compattest.WithPlugin(plugin),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = "http://localhost:3000"
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	// Step 3: expose the last link per email to the node script
	s.Mux.HandleFunc("/test/last-magic-link", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		data, ok := links[strings.ToLower(r.URL.Query().Get("email"))]
		mu.Unlock()
		if !ok {
			http.Error(w, "no magic link", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"url": data.URL, "token": data.Token})
	})

	// Step 4: run the official client script
	compattest.RunNodeClient(t, compattest.ClientDir("client"), "test-magic-link.mjs", s.URL,
		"GOAUTH_APP_ORIGIN=http://localhost:3000")
}
