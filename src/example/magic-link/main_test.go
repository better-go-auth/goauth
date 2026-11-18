package main

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	"github.com/better-go-auth/goauth/src/models"
	magiclinkservices "github.com/better-go-auth/goauth/src/plugins/magic-link/services"
)

// requestLink asks for a magic link and returns the link the plugin sent.
func requestLink(t *testing.T, c *exkit.Client, outbox *exkit.Outbox, body map[string]any) *url.URL {
	t.Helper()
	// Step 1: POST /sign-in/magic-link answers {"status": true} and sends the link
	var out struct {
		Status bool `json:"status"`
	}
	c.MustOK(c.Post("/api/auth/sign-in/magic-link", body), &out)
	if !out.Status {
		t.Fatal("sign-in/magic-link: status false")
	}
	// Step 2: read the link back from the outbox
	link, err := url.Parse(outbox.Last("magic-link", body["email"].(string)))
	if err != nil || link.Query().Get("token") == "" {
		t.Fatalf("bad link %q: %v", outbox.Last("magic-link", body["email"].(string)), err)
	}
	return link
}

// follow opens the link on the test server, like a browser clicking it.
func follow(c *exkit.Client, link *url.URL) *exkit.Response {
	return c.Get(link.Path + "?" + link.RawQuery)
}

// TestMagicLinkFlow signs a new user up through a link, then signs them in again.
func TestMagicLinkFlow(t *testing.T) {
	app, outbox, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)
	const email = "link-user@example.com"

	// Step 1: request a link for an unknown address; the link points at the base URL
	link := requestLink(t, c, outbox, map[string]any{
		"email":              email,
		"name":               "Linda",
		"callbackURL":        "/dashboard",
		"newUserCallbackURL": "/welcome",
	})
	if link.Scheme+"://"+link.Host != app.BaseURL || link.Path != "/api/auth/magic-link/verify" ||
		link.Query().Get("callbackURL") != "/dashboard" || link.Query().Get("newUserCallbackURL") != "/welcome" {
		t.Fatalf("link = %s", link)
	}

	// Step 2: opening it creates the user, sets the session cookie and redirects a new user to newUserCallbackURL
	if r := c.Get("/api/example/me"); r.Status != http.StatusUnauthorized {
		t.Fatalf("me without session: status %d, want 401", r.Status)
	}
	r := follow(c, link)
	if r.Status != http.StatusFound || r.Header.Get("Location") != app.BaseURL+"/welcome" {
		t.Fatalf("verify: %d Location=%q %s", r.Status, r.Header.Get("Location"), r.Body)
	}
	if r.Cookie("better-auth.session_token") == nil {
		t.Fatal("verify: no session cookie")
	}

	// Step 3: the session cookie opens the protected route
	var me exkit.MeOutput
	c.MustOK(c.Get("/api/example/me"), &me.Body)
	if me.Body.Email != email {
		t.Fatalf("me = %+v", me.Body)
	}

	// Step 4: the link is single use: a second click redirects with ?error=INVALID_TOKEN
	// (errorCallbackURL defaults to callbackURL)
	b := c.Fork()
	r = follow(b, link)
	if r.Status != http.StatusFound || r.Header.Get("Location") != app.BaseURL+"/dashboard?error=INVALID_TOKEN" {
		t.Fatalf("reused link: %d Location=%q", r.Status, r.Header.Get("Location"))
	}

	// Step 5: the user exists now, so the next link goes to callbackURL
	link = requestLink(t, b, outbox, map[string]any{"email": email, "callbackURL": "/dashboard", "newUserCallbackURL": "/welcome"})
	r = follow(b, link)
	if r.Status != http.StatusFound || r.Header.Get("Location") != app.BaseURL+"/dashboard" {
		t.Fatalf("existing user: %d Location=%q", r.Status, r.Header.Get("Location"))
	}
	b.MustOK(b.Get("/api/example/me"), nil)
}

// TestMagicLinkJSON shows verify without callbackURL: it answers JSON instead of redirecting (API clients).
func TestMagicLinkJSON(t *testing.T) {
	app, outbox, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)

	// Step 1: request a link and call verify with only the token
	link := requestLink(t, c, outbox, map[string]any{"email": "api@example.com"})
	r := c.Get("/api/auth/magic-link/verify?token=" + url.QueryEscape(link.Query().Get("token")))

	// Step 2: the body has the session token and the user; the cookie is set as well
	var out struct {
		Token string `json:"token"`
		User  struct {
			Email         string `json:"email"`
			EmailVerified bool   `json:"emailVerified"`
		} `json:"user"`
	}
	c.MustOK(r, &out)
	if out.Token == "" || out.User.Email != "api@example.com" || !out.User.EmailVerified {
		t.Fatalf("verify JSON = %s", r.Body)
	}

	// Step 3: the cookie opens your routes (to use the token as "Authorization: Bearer" add the bearer plugin)
	c.MustOK(c.Get("/api/example/me"), nil)
}

// TestMagicLinkErrors shows expired/invalid tokens and rejected requests.
func TestMagicLinkErrors(t *testing.T) {
	app, outbox, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)
	const email = "late@example.com"

	// Step 1: an expired link redirects to errorCallbackURL with ?error=INVALID_TOKEN and creates no user
	link := requestLink(t, c, outbox, map[string]any{"email": email, "callbackURL": "/dashboard", "errorCallbackURL": "/link-expired"})
	// tokens are stored hashed (StoreTokenHashed), so the row is found by the token's hash
	hashed := magiclinkservices.DefaultKeyHasher(link.Query().Get("token"))
	if err := app.DB.Model(&models.Verification{}).Where("identifier = ?", hashed).
		Update("expires_at", time.Now().Add(-time.Minute).UTC()).Error; err != nil {
		t.Fatal(err)
	}
	r := follow(c, link)
	if r.Status != http.StatusFound || r.Header.Get("Location") != app.BaseURL+"/link-expired?error=INVALID_TOKEN" {
		t.Fatalf("expired: %d Location=%q", r.Status, r.Header.Get("Location"))
	}
	if r.Cookie("better-auth.session_token") != nil {
		t.Fatal("expired link must not sign in")
	}

	// Step 2: a made-up token gets the same redirect
	r = c.Get("/api/auth/magic-link/verify?token=not-a-real-token&callbackURL=%2Fdashboard")
	if r.Status != http.StatusFound || r.Header.Get("Location") != app.BaseURL+"/dashboard?error=INVALID_TOKEN" {
		t.Fatalf("bad token: %d Location=%q", r.Status, r.Header.Get("Location"))
	}

	// Step 3: without callbackURL an invalid token still redirects (to "/" on the base URL)
	r = c.Get("/api/auth/magic-link/verify?token=not-a-real-token")
	if r.Status != http.StatusFound || r.Header.Get("Location") != app.BaseURL+"/?error=INVALID_TOKEN" {
		t.Fatalf("bad token, no callback: %d Location=%q", r.Status, r.Header.Get("Location"))
	}

	// Step 4: an invalid email and a callbackURL on an untrusted origin are rejected up front
	if r := c.Post("/api/auth/sign-in/magic-link", map[string]any{"email": "nope"}); r.Status != http.StatusBadRequest || r.ErrorCode() != "INVALID_EMAIL" {
		t.Fatalf("bad email: %d %s", r.Status, r.Body)
	}
	if r := c.Post("/api/auth/sign-in/magic-link", map[string]any{"email": email, "callbackURL": "https://evil.example.com/"}); r.Status != http.StatusForbidden || r.ErrorCode() != "INVALID_CALLBACK_URL" {
		t.Fatalf("untrusted callbackURL: %d %s", r.Status, r.Body)
	}
}
