// Package twofactorclient runs the official better-auth client (twoFactorClient) against goauth.
package twofactorclient

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	twofactor "github.com/better-go-auth/goauth/src/plugins/two-factor"
	tfconfig "github.com/better-go-auth/goauth/src/plugins/two-factor/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

func TestTwoFactorOfficialClient(t *testing.T) {
	// Step 1: capture the OTPs the plugin sends
	var mu sync.Mutex
	last := map[string]string{}
	plugin := twofactor.New(tfconfig.Config{
		Issuer: "GoAuth Client",
		OTPOptions: tfconfig.OTPOptions{
			SendOTP: func(_ context.Context, data tfconfig.SendOTPData, _ *http.Request) error {
				mu.Lock()
				defer mu.Unlock()
				last[strings.ToLower(data.User.Email)] = data.OTP
				return nil
			},
		},
	})

	// Step 2: start goauth with the plugin
	s := compattest.NewServer(t,
		compattest.WithPlugin(plugin),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = "http://localhost:3000"
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	// Step 3: test-only endpoint exposing the last OTP of an email
	s.Mux.HandleFunc("/test/last-otp", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		otp := last[strings.ToLower(r.URL.Query().Get("email"))]
		mu.Unlock()
		if otp == "" {
			http.Error(w, "no otp", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"otp": otp})
	})

	// Step 4: drive it with better-auth/client + twoFactorClient
	compattest.RunNodeClient(t, compattest.ClientDir("client"), "test-two-factor.mjs", s.URL, "GOAUTH_ISSUER=GoAuth Client")
}
