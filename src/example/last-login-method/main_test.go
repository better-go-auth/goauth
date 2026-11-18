package main

import (
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
)

const cookieName = "better-auth.last_used_login_method"

func TestLastLoginMethodFlow(t *testing.T) {
	app, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)

	// Step 1: email sign-up → "email", readable by JavaScript (not HttpOnly)
	r := c.MustOK(c.SignUp("alice@example.com", "Password123!", "Alice", map[string]any{"username": "alice"}), nil)
	ck := r.Cookie(cookieName)
	if ck == nil || ck.Value != "email" || ck.HttpOnly {
		t.Fatalf("after sign-up: %+v", ck)
	}
	// Step 2: username sign-in → "username" (custom resolver)
	b := c.Fork()
	r = b.MustOK(b.Post("/api/auth/sign-in/username", map[string]any{"username": "alice", "password": "Password123!"}), nil)
	if ck := r.Cookie(cookieName); ck == nil || ck.Value != "username" {
		t.Fatalf("after username sign-in: %+v", ck)
	}
	// Step 3: requests that do not sign in leave the cookie alone
	if ck := b.MustOK(b.Get("/api/auth/get-session"), nil).Cookie(cookieName); ck != nil {
		t.Fatalf("get-session set %+v", ck)
	}
}
