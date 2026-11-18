package main

import (
	"net/url"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
)

func TestOIDCProviderFlow(t *testing.T) {
	app, _, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)
	c.MustOK(c.SignUp("alice@example.com", "Password123!", "Alice Doe"), nil)

	// Step 1: the application sends the (signed-out) browser to the authorization endpoint
	browser := c.Fork()
	authorize := "/api/auth/oauth2/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {DemoClientID}, "redirect_uri": {DemoRedirectURI},
		"scope": {"openid profile email"}, "state": {"xyz"}, "nonce": {"n-1"},
	}.Encode()
	r := browser.Get(authorize)
	if r.Status != 302 || !strings.HasPrefix(r.Header.Get("Location"), "/login?") {
		t.Fatalf("authorize: %d %s", r.Status, r.Header.Get("Location"))
	}
	if page := browser.Get("/login"); !strings.Contains(string(page.Body), "/api/auth/sign-in/email") {
		t.Fatal("login page")
	}
	// Step 2: signing in on the login page continues to the consent page
	r = browser.SignIn("alice@example.com", "Password123!")
	if r.Status != 302 || !strings.HasPrefix(r.Header.Get("Location"), "/consent?consent_code=") {
		t.Fatalf("sign-in: %d %s", r.Status, r.Header.Get("Location"))
	}
	// Step 3: the user allows; the browser goes back to the application with a code
	var consent struct {
		RedirectURI string `json:"redirectURI"`
	}
	browser.MustOK(browser.Post("/api/auth/oauth2/consent", map[string]any{"accept": true}), &consent)
	back, _ := url.Parse(consent.RedirectURI)
	if !strings.HasPrefix(consent.RedirectURI, DemoRedirectURI) || back.Query().Get("state") != "xyz" {
		t.Fatalf("consent: %s", consent.RedirectURI)
	}
	// Step 4: the application exchanges the code (server to server)
	rp := c.Fork()
	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
	}
	rp.MustOK(rp.Post("/api/auth/oauth2/token", map[string]any{
		"grant_type": "authorization_code", "code": back.Query().Get("code"), "redirect_uri": DemoRedirectURI,
		"client_id": DemoClientID, "client_secret": DemoClientSecret,
	}), &tok)
	if tok.AccessToken == "" || tok.IDToken == "" || tok.TokenType != "Bearer" {
		t.Fatalf("token: %+v", tok)
	}
	// Step 5: userinfo with the access token (scope claims plus the example's extra claim)
	var info map[string]any
	rp.MustOK(rp.Get("/api/auth/oauth2/userinfo", map[string]string{"Authorization": "Bearer " + tok.AccessToken}), &info)
	if info["email"] != "alice@example.com" || info["given_name"] != "Alice" || info["locale"] != "en" {
		t.Fatalf("userinfo: %v", info)
	}
	// Step 6: the discovery document at the origin
	var md map[string]any
	c.MustOK(c.Get("/.well-known/openid-configuration"), &md)
	if md["issuer"] != exkit.DefaultBaseURL || md["token_endpoint"] != exkit.DefaultBaseURL+"/api/auth/oauth2/token" {
		t.Fatalf("discovery: %v", md)
	}
}
