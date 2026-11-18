package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
)

// redirectBody is the {url, redirect} body of /sign-in/social and /link-social.
type redirectBody struct {
	URL      string `json:"url"`
	Redirect bool   `json:"redirect"`
}

type account struct {
	ProviderID string `json:"providerId"`
	AccountID  string `json:"accountId"`
}

// fakeProvider is a generic OpenID Connect provider "fake" pointed at the in-process fake.
func fakeProvider(fake *socialtest.Provider) providers.Provider {
	return providers.Generic(providers.GenericOptions{
		ProviderID: "fake",
		Issuer:     fake.Issuer,
		ProviderOptions: providers.ProviderOptions{
			ClientID:              fake.ClientID,
			ClientSecret:          fake.ClientSecret,
			AuthorizationEndpoint: fake.AuthorizationEndpoint(),
			TokenEndpoint:         fake.TokenEndpoint(),
			UserInfoEndpoint:      fake.UserInfoEndpoint(),
			JWKSEndpoint:          fake.JWKSEndpoint(),
		},
	})
}

// authorize plays the user approving the app at the provider: it opens the authorization URL and returns
// the path (+query) of the callback the provider redirects the browser to.
func authorize(t *testing.T, c *exkit.Client, authURL string) string {
	t.Helper()
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Get(authURL)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, c.BaseURL) {
		t.Fatalf("authorize: %d %s", resp.StatusCode, loc)
	}
	return strings.TrimPrefix(loc, c.BaseURL)
}

func listAccounts(t *testing.T, c *exkit.Client) map[string]account {
	t.Helper()
	var accs []account
	c.MustOK(c.Get("/api/auth/list-accounts"), &accs)
	out := map[string]account{}
	for _, a := range accs {
		out[a.ProviderID] = a
	}
	return out
}

func TestSocialFlow(t *testing.T) {
	// Step 0: a fake OAuth provider; it sends the browser back to the test server instead of BaseURL
	fake := socialtest.New("client-id", "client-secret")
	t.Cleanup(fake.Close)
	fake.SetUser(socialtest.Profile{Sub: "gh-alice", Email: "alice@example.com", EmailVerified: true, Name: "Alice"})
	app, err := newApp("", fakeProvider(fake))
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)
	fake.SetRedirectBase(c.BaseURL)

	// Step 1: sign-in/social answers the provider's authorization URL (also as Location) and sets the state cookie
	if r := c.Get("/api/example/me"); r.Status != http.StatusUnauthorized {
		t.Fatalf("me without session: %d, want 401", r.Status)
	}
	var start redirectBody
	r := c.MustOK(c.Post("/api/auth/sign-in/social", map[string]any{
		"provider": "fake", "callbackURL": "/dashboard", "newUserCallbackURL": "/welcome",
	}), &start)
	if !start.Redirect || !strings.HasPrefix(start.URL, fake.AuthorizationEndpoint()) || r.Header.Get("Location") != start.URL {
		t.Fatalf("sign-in/social: %s", r.Body)
	}
	if r.Cookie("better-auth.state") == nil {
		t.Fatal("no state cookie")
	}

	// Step 2: the provider redirects to /api/auth/callback/fake; the callback creates the user and the
	// session, then redirects to newUserCallbackURL (callbackURL for returning users)
	cb := c.Get(authorize(t, c, start.URL))
	if cb.Status != http.StatusFound || cb.Header.Get("Location") != "/welcome" {
		t.Fatalf("callback: %d %s %s", cb.Status, cb.Header.Get("Location"), cb.Body)
	}
	if ck := cb.Cookie("better-auth.session_token"); ck == nil || ck.Value == "" {
		t.Fatal("no session cookie after the callback")
	}

	// Step 3: the session cookie opens the protected route, and the user has a "fake" account
	var me exkit.MeOutput
	c.MustOK(c.Get("/api/example/me"), &me.Body)
	if me.Body.Email != "alice@example.com" {
		t.Fatalf("me = %+v", me.Body)
	}
	if a, ok := listAccounts(t, c)["fake"]; !ok || a.AccountID != "gh-alice" {
		t.Fatalf("list-accounts: %+v", listAccounts(t, c))
	}

	// Step 4: the provider's access token is available to the server (refreshed when expired)
	var tok struct {
		AccessToken string `json:"accessToken"`
	}
	c.MustOK(c.Post("/api/auth/get-access-token", map[string]any{"providerId": "fake"}), &tok)
	if !fake.IsAccessToken(tok.AccessToken) {
		t.Fatalf("get-access-token: %q is not the provider's token", tok.AccessToken)
	}

	// Step 5: signing in again reuses the account and goes to callbackURL
	c.Reset()
	c.MustOK(c.Post("/api/auth/sign-in/social", map[string]any{"provider": "fake", "callbackURL": "/dashboard", "newUserCallbackURL": "/welcome"}), &start)
	if cb := c.Get(authorize(t, c, start.URL)); cb.Header.Get("Location") != "/dashboard" {
		t.Fatalf("returning user: %d %s", cb.Status, cb.Header.Get("Location"))
	}

	// Step 6: an email/password user links the provider to their account with link-social
	bob := c.Fork()
	if r := bob.Post("/api/auth/link-social", map[string]any{"provider": "fake"}); r.Status != http.StatusUnauthorized {
		t.Fatalf("link-social without session: %d, want 401", r.Status)
	}
	bob.MustOK(bob.SignUp("bob@example.com", "Password123!", "Bob"), nil)
	fake.SetUser(socialtest.Profile{Sub: "gh-bob", Email: "bob@example.com", EmailVerified: true, Name: "Bob"})
	var link redirectBody
	bob.MustOK(bob.Post("/api/auth/link-social", map[string]any{"provider": "fake", "callbackURL": "/settings"}), &link)
	if cb := bob.Get(authorize(t, bob, link.URL)); cb.Status != http.StatusFound || cb.Header.Get("Location") != "/settings" {
		t.Fatalf("link callback: %d %s", cb.Status, cb.Header.Get("Location"))
	}
	accs := listAccounts(t, bob)
	if _, ok := accs["credential"]; !ok || accs["fake"].AccountID != "gh-bob" {
		t.Fatalf("bob's accounts: %+v", accs)
	}

	// Step 7: an unknown provider gives better-auth's error code
	if r := c.Post("/api/auth/sign-in/social", map[string]any{"provider": "nope"}); r.Status != http.StatusNotFound || r.ErrorCode() != "PROVIDER_NOT_FOUND" {
		t.Fatalf("unknown provider: %d %s", r.Status, r.Body)
	}
}
