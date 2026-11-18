package main

import (
	"net/http"
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
)

type userBody struct {
	ID              string  `json:"id"`
	Email           string  `json:"email"`
	Username        *string `json:"username"`
	DisplayUsername *string `json:"displayUsername"`
}

func TestUsernameFlow(t *testing.T) {
	app, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)

	// Step 1: the username is free
	var avail struct {
		Available bool `json:"available"`
	}
	c.MustOK(c.Post("/api/auth/is-username-available", map[string]any{"username": "Alice_01"}), &avail)
	if !avail.Available {
		t.Fatal("username should be available")
	}

	// Step 2: sign up with a username; it is stored lowercased, displayUsername keeps the original
	var signUp struct {
		User userBody `json:"user"`
	}
	c.MustOK(c.SignUp("alice@example.com", "Password123!", "Alice", map[string]any{"username": "Alice_01"}), &signUp)
	if signUp.User.Username == nil || *signUp.User.Username != "alice_01" {
		t.Fatalf("username = %v, want alice_01", signUp.User.Username)
	}
	if signUp.User.DisplayUsername == nil || *signUp.User.DisplayUsername != "Alice_01" {
		t.Fatalf("displayUsername = %v, want Alice_01", signUp.User.DisplayUsername)
	}

	// Step 3: now it is taken, and invalid usernames are rejected
	c.MustOK(c.Post("/api/auth/is-username-available", map[string]any{"username": "alice_01"}), &avail)
	if avail.Available {
		t.Fatal("username should be taken")
	}
	if r := c.Post("/api/auth/is-username-available", map[string]any{"username": "no spaces"}); r.Status != http.StatusUnprocessableEntity && r.Status != http.StatusBadRequest {
		t.Fatalf("invalid username: status %d (%s)", r.Status, r.Body)
	}

	// Step 4: a new browser signs in with the username (any case) instead of the email
	b := c.Fork()
	if r := b.Get("/api/example/me"); r.Status != http.StatusUnauthorized {
		t.Fatalf("me without session: status %d, want 401", r.Status)
	}
	b.MustOK(b.Post("/api/auth/sign-in/username", map[string]any{"username": "ALICE_01", "password": "Password123!"}), nil)

	// Step 5: the session cookie opens the protected route
	var me exkit.MeOutput
	b.MustOK(b.Get("/api/example/me"), &me.Body)
	if me.Body.Email != "alice@example.com" {
		t.Fatalf("me = %+v", me.Body)
	}

	// Step 6: a wrong password gives better-auth's error code
	if r := c.Fork().Post("/api/auth/sign-in/username", map[string]any{"username": "alice_01", "password": "wrong-password"}); r.Status != http.StatusUnauthorized || r.ErrorCode() != "INVALID_USERNAME_OR_PASSWORD" {
		t.Fatalf("wrong password: %d %s", r.Status, r.Body)
	}
}
