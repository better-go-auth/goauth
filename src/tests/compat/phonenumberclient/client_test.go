// Package phonenumberclient runs the official better-auth client (phoneNumberClient) against goauth.
package phonenumberclient

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	phonenumber "github.com/better-go-auth/goauth/src/plugins/phone-number"
	phoneconfig "github.com/better-go-auth/goauth/src/plugins/phone-number/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

func TestOfficialClientPhoneNumber(t *testing.T) {
	// Step 1: capture the codes the plugin "sends" by SMS
	var mu sync.Mutex
	otps := map[string]string{}
	resets := map[string]string{}
	record := func(m map[string]string) phoneconfig.SendOTPFunc {
		return func(d phoneconfig.OTPData, _ *http.Request) error {
			mu.Lock()
			defer mu.Unlock()
			m[d.PhoneNumber] = d.Code
			return nil
		}
	}

	// Step 2: start goauth with the phone-number plugin (sign-up on verification, "+" numbers only)
	p := phonenumber.New(phoneconfig.PhoneNumberConfig{
		SendOTP:              record(otps),
		SendPasswordResetOTP: record(resets),
		PhoneNumberValidator: func(phone string) bool { return strings.HasPrefix(phone, "+") && len(phone) >= 8 },
		SignUpOnVerification: &phoneconfig.SignUpOnVerification{
			GetTempEmail: func(phone string) string { return strings.TrimPrefix(phone, "+") + "@phone.example.invalid" },
		},
	})
	s := compattest.NewServer(t,
		compattest.WithPlugin(p),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = "http://localhost:3000"
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	// Step 3: test-only endpoint the script reads codes from (?phone=...&type=otp|reset)
	s.Mux.HandleFunc("/test/last-sms", func(w http.ResponseWriter, r *http.Request) {
		phone := r.URL.Query().Get("phone")
		box := otps
		if r.URL.Query().Get("type") == "reset" {
			box = resets
		}
		mu.Lock()
		code := box[phone]
		mu.Unlock()
		if code == "" {
			http.Error(w, "no sms", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"code": code})
	})

	// Step 4: run the official client script
	compattest.RunNodeClient(t, compattest.ClientDir("client"), "test-phone-number.mjs", s.URL)
}
