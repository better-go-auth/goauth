package main

import (
	"net/http"
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
)

type tokenBody struct {
	Token string `json:"token"`
}

type sessionBody struct {
	Session struct {
		Token  string `json:"token"`
		UserID string `json:"userId"`
	} `json:"session"`
	User struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
}

func TestOneTimeTokenFlow(t *testing.T) {
	app, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)

	// Step 1: generating a token needs a session
	if r := c.Get("/api/auth/one-time-token/generate"); r.Status != http.StatusUnauthorized {
		t.Fatalf("generate without session: status %d, want 401", r.Status)
	}

	// Step 2: the user signs up; with SetOttHeaderOnNewSession the response already carries a token
	var signUp struct {
		Token string `json:"token"`
		User  struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	r := c.MustOK(c.SignUp("alice@example.com", "Password123!", "Alice"), &signUp)
	setOtt := r.Header.Get("set-ott")
	if setOtt == "" {
		t.Fatalf("sign-up response has no set-ott header: %v", r.Header)
	}

	// Step 3: the signed-in browser asks for a one-time token
	var gen tokenBody
	c.MustOK(c.Get("/api/auth/one-time-token/generate"), &gen)
	if len(gen.Token) != 32 {
		t.Fatalf("token = %q, want 32 characters", gen.Token)
	}

	// Step 4: another client without cookies exchanges it for the same session (and its cookie)
	other := c.Fork()
	if r := other.Get("/api/example/me"); r.Status != http.StatusUnauthorized {
		t.Fatalf("me before verify: status %d, want 401", r.Status)
	}
	var sess sessionBody
	r = other.MustOK(other.Post("/api/auth/one-time-token/verify", map[string]any{"token": gen.Token}), &sess)
	if sess.Session.Token != signUp.Token || sess.User.ID != signUp.User.ID || sess.User.Email != "alice@example.com" {
		t.Fatalf("verify body = %s", r.Body)
	}
	if r.Cookie("better-auth.session_token") == nil {
		t.Fatalf("verify must set the session cookie: %v", r.Header.Values("Set-Cookie"))
	}

	// Step 5: the second client is now signed in as the same user
	var me exkit.MeOutput
	other.MustOK(other.Get("/api/example/me"), &me.Body)
	if me.Body.UserID != signUp.User.ID {
		t.Fatalf("me = %+v", me.Body)
	}

	// Step 6: the token works once
	if r := c.Fork().Post("/api/auth/one-time-token/verify", map[string]any{"token": gen.Token}); r.Status != http.StatusBadRequest || r.ErrorCode() != "INVALID_TOKEN" {
		t.Fatalf("reused token: %d %s", r.Status, r.Body)
	}

	// Step 7: the set-ott token from sign-up works too (once)
	third := c.Fork()
	third.MustOK(third.Post("/api/auth/one-time-token/verify", map[string]any{"token": setOtt}), nil)
}
