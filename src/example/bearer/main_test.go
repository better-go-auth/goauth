package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
)

// bearerClient returns a client without cookies that sends Authorization: Bearer <token>.
func bearerClient(c *exkit.Client, token string) *exkit.Client {
	b := c.Fork()
	b.HTTP.Jar = nil // never keep cookies: the bearer header is the only credential
	b.Headers = map[string]string{"Authorization": "Bearer " + token}
	return b
}

type signInBody struct {
	Token string `json:"token"`
	User  struct {
		ID string `json:"id"`
	} `json:"user"`
}

func TestBearerFlow(t *testing.T) {
	app, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)
	c.HTTP.Jar = nil // a mobile app or CLI: no cookie jar

	// Step 1: sign up, then sign in; every response that sets the session cookie also sends set-auth-token
	c.MustOK(c.SignUp("alice@example.com", "Password123!", "Alice"), nil)
	var body signInBody
	r := c.MustOK(c.SignIn("alice@example.com", "Password123!"), &body)
	token := r.Header.Get("set-auth-token")
	if token == "" || !strings.HasPrefix(token, body.Token+".") {
		t.Fatalf("set-auth-token = %q, want %q.<signature>", token, body.Token)
	}
	if !strings.Contains(r.Header.Get("Access-Control-Expose-Headers"), "set-auth-token") {
		t.Fatalf("set-auth-token must be exposed to browsers: %v", r.Header)
	}

	// Step 2: without a cookie or token the protected route answers 401
	if r := c.Get("/api/example/me"); r.Status != http.StatusUnauthorized {
		t.Fatalf("me without credentials: status %d, want 401", r.Status)
	}

	// Step 3: the bearer token opens your own routes and goauth's routes
	b := bearerClient(c, token)
	var me exkit.MeOutput
	b.MustOK(b.Get("/api/example/me"), &me.Body)
	if me.Body.UserID != body.User.ID || me.Body.Email != "alice@example.com" {
		t.Fatalf("me = %+v", me.Body)
	}
	var sess struct {
		User struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	b.MustOK(b.Get("/api/auth/get-session"), &sess)
	if sess.User.Email != "alice@example.com" {
		t.Fatalf("get-session = %+v", sess)
	}

	// Step 4: with RequireSignature (the default) the raw session token from the body is rejected,
	// and so is a token with a forged signature
	if r := bearerClient(c, body.Token).Get("/api/example/me"); r.Status != http.StatusUnauthorized {
		t.Fatalf("unsigned token: status %d, want 401", r.Status)
	}
	if r := bearerClient(c, body.Token+".forged").Get("/api/example/me"); r.Status != http.StatusUnauthorized {
		t.Fatalf("forged signature: status %d, want 401", r.Status)
	}

	// Step 5: signing out with the bearer token ends the session
	b.MustOK(b.Post("/api/auth/sign-out", map[string]any{}), nil)
	if r := b.Get("/api/example/me"); r.Status != http.StatusUnauthorized {
		t.Fatalf("me after sign-out: status %d, want 401", r.Status)
	}
}

func TestBearerWithoutSignature(t *testing.T) {
	// Step 1: RequireSignature false also accepts the raw session token (the "token" field of sign-in)
	requireSignature := false
	app, err := newAppWithConfig("", bearerconfig.BearerConfig{RequireSignature: &requireSignature})
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)
	c.HTTP.Jar = nil
	var body signInBody
	c.MustOK(c.SignUp("bob@example.com", "Password123!", "Bob"), &body)

	// Step 2: the raw token works
	b := bearerClient(c, body.Token)
	var me exkit.MeOutput
	b.MustOK(b.Get("/api/example/me"), &me.Body)
	if me.Body.UserID != body.User.ID {
		t.Fatalf("me = %+v", me.Body)
	}

	// Step 3: a signed token with a bad signature is still rejected
	if r := bearerClient(c, body.Token+".forged").Get("/api/example/me"); r.Status != http.StatusUnauthorized {
		t.Fatalf("forged signature: status %d, want 401", r.Status)
	}
}
