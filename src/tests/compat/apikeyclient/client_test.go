// Package apikeyclient runs the official better-auth client with @better-auth/api-key's apiKeyClient()
// against goauth's api-key plugin, and compares the plugin's error codes and key hashing with the
// installed package.
package apikeyclient

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	apikey "github.com/better-go-auth/goauth/src/plugins/api-key"
	apikeyconfig "github.com/better-go-auth/goauth/src/plugins/api-key/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

// pageOrigin is the origin the Node client claims.
const pageOrigin = "http://localhost:3000"

func TestOfficialClientAPIKey(t *testing.T) {
	// Step 1: goauth with metadata and sessions from API keys enabled
	p := apikey.New(apikeyconfig.Configuration{EnableMetadata: true, EnableSessionForAPIKeys: true})
	s := compattest.NewServer(t,
		compattest.WithPlugin(p),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = pageOrigin
			c.TrustedOrigins = append(c.TrustedOrigins, pageOrigin, "http://127.0.0.1:*")
		}),
	)
	// Step 2: a server-side key allowing a single request (rate-limit check of the script)
	owner := signUp(t, s)
	rk, err := p.CreateAPIKey(context.Background(), apikey.CreateAPIKeyInput{UserID: &owner, RateLimitMax: ptr[int64](1)})
	if err != nil {
		t.Fatal(err)
	}
	// Step 3: run the official client script
	compattest.RunNodeClient(t, compattest.ClientDir("client-apikey"), "test-api-key.mjs", s.URL,
		"PAGE_ORIGIN="+pageOrigin, "RATE_KEY="+rk.Key)
}

// signUp creates a user through the server and returns its id.
func signUp(t *testing.T, s *compattest.Server) string {
	t.Helper()
	r := s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": "rate-owner@example.com", "password": "Password123!", "name": "Rate"})
	var body struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	r.JSON(t, &body)
	if body.User.ID == "" {
		t.Fatalf("sign-up: %d %s", r.Status, r.Body)
	}
	return body.User.ID
}

// TestErrorCodesAndHashMatchPackage compares API_KEY_ERROR_CODES and defaultKeyHasher with the package.
func TestErrorCodesAndHashMatchPackage(t *testing.T) {
	out := compattest.RunNodeClient(t, compattest.ClientDir("client-apikey"), "dump-error-codes.mjs", "http://unused")
	var dump struct {
		Codes  map[string]string `json:"codes"`
		Hashes map[string]string `json:"hashes"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &dump); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	// Step 1: the same codes with the same messages
	if len(dump.Codes) != len(apikey.ErrorCodes) {
		t.Errorf("codes: package %d, goauth %d", len(dump.Codes), len(apikey.ErrorCodes))
	}
	for code, msg := range dump.Codes {
		if apikey.ErrorCodes[code] != msg {
			t.Errorf("%s: package %q, goauth %q", code, msg, apikey.ErrorCodes[code])
		}
	}
	// Step 2: the same hashes
	for key, want := range dump.Hashes {
		if got := apikey.HashKey(key); got != want {
			t.Errorf("HashKey(%q) = %q, package %q", key, got, want)
		}
	}
}

func ptr[T any](v T) *T { return &v }
