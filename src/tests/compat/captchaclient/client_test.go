// Package captchaclient runs the official better-auth client against goauth's captcha plugin (the client
// sends the token in the x-captcha-response header through fetchOptions; there is no captcha client plugin).
package captchaclient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins/captcha"
	captchaconfig "github.com/better-go-auth/goauth/src/plugins/captcha/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

func TestOfficialClientCaptcha(t *testing.T) {
	// Step 1: a fake Cloudflare Turnstile accepting "good-token"
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Response string `json:"response"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"success": body.Response == "good-token"})
	}))
	t.Cleanup(provider.Close)

	// Step 2: goauth with the captcha plugin
	s := compattest.NewServer(t,
		compattest.WithPlugin(captcha.New(captchaconfig.CaptchaConfig{
			Provider: captchaconfig.CloudflareTurnstile, SecretKey: "secret", SiteVerifyURLOverride: provider.URL,
		})),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = "http://localhost:3000"
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	// Step 3: run the official client script
	compattest.RunNodeClient(t, compattest.ClientDir("client"), "test-captcha.mjs", s.URL)
}
