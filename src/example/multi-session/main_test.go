package main

import (
	"net/http"
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
)

const password = "Password123!"

// deviceSession is one entry of list-device-sessions.
type deviceSession struct {
	Session struct {
		Token  string `json:"token"`
		UserID string `json:"userId"`
	} `json:"session"`
	User struct {
		Email string `json:"email"`
	} `json:"user"`
}

// deviceSessions returns the browser's sessions by email.
func deviceSessions(t *testing.T, c *exkit.Client) map[string]deviceSession {
	t.Helper()
	var list []deviceSession
	c.MustOK(c.Get("/api/auth/multi-session/list-device-sessions"), &list)
	out := map[string]deviceSession{}
	for _, s := range list {
		out[s.User.Email] = s
	}
	return out
}

// mustBe checks that the browser's active session belongs to email.
func mustBe(t *testing.T, c *exkit.Client, email string) {
	t.Helper()
	var me exkit.MeOutput
	c.MustOK(c.Get("/api/example/me"), &me.Body)
	if me.Body.Email != email {
		t.Fatalf("active user = %s, want %s", me.Body.Email, email)
	}
}

func TestMultiSessionFlow(t *testing.T) {
	app, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)

	// Step 1: two users sign in in the same browser; the last sign-in is the active session
	c.MustOK(c.SignUp("alice@example.com", password, "Alice"), nil)
	c.MustOK(c.SignUp("bob@example.com", password, "Bob"), nil)
	mustBe(t, c, "bob@example.com")

	// Step 2: the browser lists both sessions (one multi-session cookie each)
	sessions := deviceSessions(t, c)
	if len(sessions) != 2 {
		t.Fatalf("device sessions = %+v", sessions)
	}
	alice, bob := sessions["alice@example.com"], sessions["bob@example.com"]

	// Step 3: switch the active session to Alice without signing in again
	var active deviceSession
	c.MustOK(c.Post("/api/auth/multi-session/set-active", map[string]any{"sessionToken": alice.Session.Token}), &active)
	if active.User.Email != "alice@example.com" {
		t.Fatalf("set-active = %+v", active)
	}
	mustBe(t, c, "alice@example.com")

	// Step 4: another browser cannot use a token it has no multi-session cookie for
	if r := c.Fork().Post("/api/auth/multi-session/set-active", map[string]any{"sessionToken": bob.Session.Token}); r.Status != http.StatusUnauthorized || r.ErrorCode() != "INVALID_SESSION_TOKEN" {
		t.Fatalf("set-active from another browser: %d %s", r.Status, r.Body)
	}

	// Step 5: revoking the active session switches the browser to the next one (Bob)
	c.MustOK(c.Post("/api/auth/multi-session/revoke", map[string]any{"sessionToken": alice.Session.Token}), nil)
	mustBe(t, c, "bob@example.com")
	if s := deviceSessions(t, c); len(s) != 1 {
		t.Fatalf("after revoke: %+v", s)
	}
	if r := c.Post("/api/auth/multi-session/set-active", map[string]any{"sessionToken": alice.Session.Token}); r.ErrorCode() != "INVALID_SESSION_TOKEN" {
		t.Fatalf("set-active of a revoked session: %d %s", r.Status, r.Body)
	}

	// Step 6: Alice signs in again; revoking a non-active session leaves the active one alone
	c.MustOK(c.SignIn("alice@example.com", password), nil)
	sessions = deviceSessions(t, c)
	if len(sessions) != 2 {
		t.Fatalf("device sessions = %+v", sessions)
	}
	c.MustOK(c.Post("/api/auth/multi-session/revoke", map[string]any{"sessionToken": sessions["bob@example.com"].Session.Token}), nil)
	mustBe(t, c, "alice@example.com")

	// Step 7: sign-out signs every account of the browser out
	c.MustOK(c.SignIn("bob@example.com", password), nil)
	c.MustOK(c.Post("/api/auth/sign-out", map[string]any{}), nil)
	if s := deviceSessions(t, c); len(s) != 0 {
		t.Fatalf("after sign-out: %+v", s)
	}
	if r := c.Get("/api/example/me"); r.Status != http.StatusUnauthorized {
		t.Fatalf("me after sign-out: status %d, want 401", r.Status)
	}
}
