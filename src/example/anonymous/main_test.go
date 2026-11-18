package main

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
)

type userBody struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Email       string `json:"email"`
	IsAnonymous bool   `json:"isAnonymous"`
}

type authBody struct {
	Token string   `json:"token"`
	User  userBody `json:"user"`
}

type notesBody struct {
	Notes []string `json:"notes"`
}

func TestAnonymousFlow(t *testing.T) {
	app, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)
	userExists := func(id string) bool {
		u, err := app.Auth.Repositories().FindUserByID(context.Background(), id)
		return err == nil && u != nil
	}

	// Step 1: a visitor signs in anonymously and gets a session cookie and an anonymous user
	var anon authBody
	c.MustOK(c.Post("/api/auth/sign-in/anonymous", nil), &anon)
	if !anon.User.IsAnonymous || anon.User.Name != "Guest" || !strings.HasSuffix(anon.User.Email, "@guest.example.com") {
		t.Fatalf("anonymous user = %+v", anon.User)
	}

	// Step 2: the session opens protected routes like any other session
	var me exkit.MeOutput
	c.MustOK(c.Get("/api/example/me"), &me.Body)
	if me.Body.UserID != anon.User.ID {
		t.Fatalf("me = %+v, want user %s", me.Body, anon.User.ID)
	}
	var session struct {
		User userBody `json:"user"`
	}
	c.MustOK(c.Get("/api/auth/get-session"), &session)
	if !session.User.IsAnonymous {
		t.Fatalf("get-session user = %+v, want isAnonymous", session.User)
	}

	// Step 3: the anonymous user creates some data of its own
	c.MustOK(c.Post("/api/example/notes", map[string]any{"text": "buy milk"}), nil)

	// Step 4: an anonymous user can't sign in anonymously again
	if r := c.Post("/api/auth/sign-in/anonymous", nil); r.Status != http.StatusBadRequest || r.ErrorCode() != "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY" {
		t.Fatalf("second anonymous sign-in: %d %s", r.Status, r.Body)
	}

	// Step 5: signing up while anonymous links the account: OnLinkAccount moves the notes and the
	// anonymous user is deleted
	var real authBody
	c.MustOK(c.SignUp("alice@example.com", "Password123!", "Alice"), &real)
	if real.User.IsAnonymous || real.User.ID == anon.User.ID {
		t.Fatalf("new user = %+v", real.User)
	}
	if userExists(anon.User.ID) {
		t.Fatal("the anonymous user must be deleted after linking")
	}

	// Step 6: the new session is the real, non-anonymous user, and the notes came along
	c.MustOK(c.Get("/api/auth/get-session"), &session)
	if session.User.ID != real.User.ID || session.User.IsAnonymous {
		t.Fatalf("session user after linking = %+v", session.User)
	}
	var n notesBody
	c.MustOK(c.Get("/api/example/notes"), &n)
	if len(n.Notes) != 1 || n.Notes[0] != "buy milk" {
		t.Fatalf("notes after linking = %v", n.Notes)
	}

	// Step 7: a real user can't use /delete-anonymous-user
	if r := c.Post("/api/auth/delete-anonymous-user", nil); r.Status != http.StatusForbidden || r.ErrorCode() != "USER_IS_NOT_ANONYMOUS" {
		t.Fatalf("delete as real user: %d %s", r.Status, r.Body)
	}

	// Step 8: another visitor signs in anonymously and deletes their own anonymous user
	b := c.Fork()
	var anon2 authBody
	b.MustOK(b.Post("/api/auth/sign-in/anonymous", nil), &anon2)
	var del struct {
		Success bool `json:"success"`
	}
	b.MustOK(b.Post("/api/auth/delete-anonymous-user", nil), &del)
	if !del.Success || userExists(anon2.User.ID) {
		t.Fatalf("delete-anonymous-user: success=%v, user still exists=%v", del.Success, userExists(anon2.User.ID))
	}
	if r := b.Get("/api/example/me"); r.Status != http.StatusUnauthorized {
		t.Fatalf("me after delete: status %d, want 401", r.Status)
	}
}
