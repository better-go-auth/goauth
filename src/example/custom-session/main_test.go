package main

import (
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
)

func TestCustomSessionFlow(t *testing.T) {
	app, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)

	// Step 1: without a session the response stays null
	r := c.MustOK(c.Get("/api/auth/get-session"), nil)
	if strings.TrimSpace(string(r.Body)) != "null" {
		t.Fatalf("anonymous get-session = %s", r.Body)
	}
	// Step 2: signed in, the callback's value is returned
	c.MustOK(c.SignUp("alice@example.com", "Password123!", "Alice"), nil)
	var body struct {
		Roles   []string `json:"roles"`
		Display string   `json:"display"`
		User    struct {
			Email string `json:"email"`
		} `json:"user"`
		Session struct {
			Token string `json:"token"`
		} `json:"session"`
	}
	c.MustOK(c.Get("/api/auth/get-session"), &body)
	if len(body.Roles) != 2 || body.Roles[1] != "staff" || body.Display != "ALICE" ||
		body.User.Email != "alice@example.com" || body.Session.Token == "" {
		t.Fatalf("custom session = %+v", body)
	}
}
