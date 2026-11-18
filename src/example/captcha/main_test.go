package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
)

// fakeTurnstile accepts the token "good-token" and rejects everything else, like Cloudflare's siteverify.
func fakeTurnstile(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Secret   string `json:"secret"`
			Response string `json:"response"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		ok := body.Secret == "example-secret" && body.Response == "good-token"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"success": ok})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCaptchaFlow(t *testing.T) {
	app, err := newApp("", "example-secret", fakeTurnstile(t).URL)
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)

	// Step 1: without the header the request never reaches sign-up
	r := c.SignUp("alice@example.com", "Password123!", "Alice")
	if r.Status != http.StatusBadRequest || r.ErrorCode() != "MISSING_RESPONSE" {
		t.Fatalf("no token: %d %s", r.Status, r.Body)
	}
	// Step 2: a token the provider rejects
	r = c.Post("/api/auth/sign-up/email", map[string]any{"email": "alice@example.com", "password": "Password123!", "name": "Alice"},
		map[string]string{"x-captcha-response": "bad-token"})
	if r.Status != http.StatusForbidden || r.ErrorCode() != "VERIFICATION_FAILED" {
		t.Fatalf("bad token: %d %s", r.Status, r.Body)
	}
	// Step 3: a valid token signs the user up
	c.MustOK(c.Post("/api/auth/sign-up/email", map[string]any{"email": "alice@example.com", "password": "Password123!", "name": "Alice"},
		map[string]string{"x-captcha-response": "good-token"}), nil)
	var me exkit.MeOutput
	c.MustOK(c.Get("/api/example/me"), &me.Body)
	if me.Body.Email != "alice@example.com" {
		t.Fatalf("me = %+v", me.Body)
	}
	// Step 4: routes that are not protected need no token
	c.MustOK(c.Get("/api/auth/get-session"), nil)
}
