package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
)

const clientID = "example-client.apps.googleusercontent.com"

func TestOneTapFlow(t *testing.T) {
	// Step 1: a fake Google that signs ID tokens like accounts.google.com
	google := socialtest.New(clientID, "unused")
	google.Issuer = "https://accounts.google.com"
	t.Cleanup(google.Close)
	app, err := newApp("", clientID, google.JWKSEndpoint())
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)

	// Step 2: the page renders the One Tap prompt for our client ID
	if r := c.Get("/"); r.Status != http.StatusOK || !strings.Contains(string(r.Body), clientID) {
		t.Fatalf("page: %d", r.Status)
	}

	// Step 3: the browser posts the ID token Google returned: the user is created and signed in
	idToken := google.SignIDToken(socialtest.Profile{Sub: "g-123", Email: "Ada@Example.com", EmailVerified: true, Name: "Ada"}, "", nil)
	var out struct {
		Token string `json:"token"`
		User  struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	c.MustOK(c.Post("/api/auth/one-tap/callback", map[string]any{"idToken": idToken}), &out)
	if out.Token == "" || out.User.Email != "ada@example.com" {
		t.Fatalf("callback = %+v", out)
	}

	// Step 4: the session cookie opens the protected route
	var me exkit.MeOutput
	c.MustOK(c.Get("/api/example/me"), &me.Body)
	if me.Body.Email != "ada@example.com" {
		t.Fatalf("me = %+v", me.Body)
	}

	// Step 5: a token for another client is refused
	other := google.SignIDToken(socialtest.Profile{Sub: "g-123", Email: "ada@example.com", EmailVerified: true}, "", map[string]any{"aud": "someone-else"})
	if r := c.Fork().Post("/api/auth/one-tap/callback", map[string]any{"idToken": other}); r.Status != http.StatusBadRequest {
		t.Fatalf("other audience: %d %s", r.Status, r.Body)
	}
}
