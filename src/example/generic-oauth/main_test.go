package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
)

// redirectBody is the {url, redirect} body of /sign-in/oauth2 and /oauth2/link.
type redirectBody struct {
	URL      string `json:"url"`
	Redirect bool   `json:"redirect"`
}

type account struct {
	ProviderID string `json:"providerId"`
	AccountID  string `json:"accountId"`
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

func TestGenericOAuthFlow(t *testing.T) {
	// Step 0: a fake OpenID Connect provider, configured through its discovery document like main() does;
	// it sends the browser back to the test server instead of BaseURL
	fake := socialtest.New("client-id", "client-secret")
	t.Cleanup(fake.Close)
	fake.SetUser(socialtest.Profile{Sub: "idp-alice", Email: "alice@example.com", EmailVerified: true, Name: "Alice"})
	provider := providerFromEnv()
	provider.DiscoveryURL, provider.ClientID, provider.ClientSecret = fake.DiscoveryURL(), fake.ClientID, fake.ClientSecret
	app, err := newApp("", provider)
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)
	fake.SetRedirectBase(c.BaseURL)

	// Step 1: sign-in/oauth2 answers the provider's authorization URL (endpoints from the discovery document)
	if r := c.Get("/api/example/me"); r.Status != http.StatusUnauthorized {
		t.Fatalf("me without session: %d, want 401", r.Status)
	}
	var start redirectBody
	r := c.MustOK(c.Post("/api/auth/sign-in/oauth2", map[string]any{
		"providerId": "my-idp", "callbackURL": "/dashboard", "newUserCallbackURL": "/welcome",
	}), &start)
	u, _ := url.Parse(start.URL)
	if !start.Redirect || !strings.HasPrefix(start.URL, fake.AuthorizationEndpoint()+"?") ||
		u.Query().Get("redirect_uri") != exkit.DefaultBaseURL+"/api/auth/oauth2/callback/my-idp" || u.Query().Get("code_challenge") == "" {
		t.Fatalf("sign-in/oauth2: %s", r.Body)
	}

	// Step 2: the provider redirects to /api/auth/oauth2/callback/my-idp; the callback creates the user and
	// the session, then redirects to newUserCallbackURL (callbackURL for returning users)
	cb := c.Get(authorize(t, c, start.URL))
	if cb.Status != http.StatusFound || cb.Header.Get("Location") != "/welcome" {
		t.Fatalf("callback: %d %s %s", cb.Status, cb.Header.Get("Location"), cb.Body)
	}
	if ck := cb.Cookie("better-auth.session_token"); ck == nil || ck.Value == "" {
		t.Fatal("no session cookie after the callback")
	}

	// Step 3: the session cookie opens the protected route, and the user has a "my-idp" account
	var me exkit.MeOutput
	c.MustOK(c.Get("/api/example/me"), &me.Body)
	if me.Body.Email != "alice@example.com" {
		t.Fatalf("me = %+v", me.Body)
	}
	if a, ok := listAccounts(t, c)["my-idp"]; !ok || a.AccountID != "idp-alice" {
		t.Fatalf("list-accounts: %+v", listAccounts(t, c))
	}

	// Step 4: signing in again reuses the account and goes to callbackURL
	c.Reset()
	c.MustOK(c.Post("/api/auth/sign-in/oauth2", map[string]any{"providerId": "my-idp", "callbackURL": "/dashboard", "newUserCallbackURL": "/welcome"}), &start)
	if cb := c.Get(authorize(t, c, start.URL)); cb.Header.Get("Location") != "/dashboard" {
		t.Fatalf("returning user: %d %s", cb.Status, cb.Header.Get("Location"))
	}

	// Step 5: an email/password user links the provider to their account with oauth2/link
	bob := c.Fork()
	if r := bob.Post("/api/auth/oauth2/link", map[string]any{"providerId": "my-idp", "callbackURL": "/settings"}); r.Status != http.StatusUnauthorized {
		t.Fatalf("oauth2/link without session: %d, want 401", r.Status)
	}
	bob.MustOK(bob.SignUp("bob@example.com", "Password123!", "Bob"), nil)
	fake.SetUser(socialtest.Profile{Sub: "idp-bob", Email: "bob@example.com", EmailVerified: true, Name: "Bob"})
	var link redirectBody
	bob.MustOK(bob.Post("/api/auth/oauth2/link", map[string]any{"providerId": "my-idp", "callbackURL": "/settings"}), &link)
	if cb := bob.Get(authorize(t, bob, link.URL)); cb.Status != http.StatusFound || cb.Header.Get("Location") != "/settings" {
		t.Fatalf("link callback: %d %s", cb.Status, cb.Header.Get("Location"))
	}
	accs := listAccounts(t, bob)
	if _, ok := accs["credential"]; !ok || accs["my-idp"].AccountID != "idp-bob" {
		t.Fatalf("bob's accounts: %+v", accs)
	}

	// Step 6: the provider refusing the request redirects to the error page with its error code
	fake.SetAuthorizeError("access_denied")
	c.MustOK(c.Post("/api/auth/sign-in/oauth2", map[string]any{"providerId": "my-idp", "callbackURL": "/dashboard"}), &start)
	if cb := c.Get(authorize(t, c, start.URL)); cb.Status != http.StatusFound || !strings.Contains(cb.Header.Get("Location"), "/api/auth/error?error=access_denied") {
		t.Fatalf("denied: %d %s", cb.Status, cb.Header.Get("Location"))
	}

	// Step 7: an unknown provider gives better-auth's error code
	if r := c.Post("/api/auth/sign-in/oauth2", map[string]any{"providerId": "nope"}); r.Status != http.StatusBadRequest || r.ErrorCode() != "PROVIDER_CONFIG_NOT_FOUND" {
		t.Fatalf("unknown provider: %d %s", r.Status, r.Body)
	}
}
