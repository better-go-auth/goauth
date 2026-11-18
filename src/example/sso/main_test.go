package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
)

func TestSSOFlow(t *testing.T) {
	// Step 1: a fake OIDC identity provider (discovery, authorize, token, userinfo, JWKS)
	idp := socialtest.New("example-client", "example-secret")
	t.Cleanup(idp.Close)
	idp.SetUser(socialtest.Profile{Sub: "emp-1", Email: "jane@acme.example", EmailVerified: true, Name: "Jane Employee"})
	app, err := newApp(appOptions{TrustedOrigins: []string{"http://127.0.0.1:*"}})
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)
	idp.SetRedirectBase(c.BaseURL)

	// Step 2: an admin creates the organization and registers the company's IdP for it
	c.MustOK(c.SignUp("admin@acme.example", "Password123!", "Admin"), nil)
	var orgOut struct {
		ID string `json:"id"`
	}
	c.MustOK(c.Post("/api/auth/organization/create", map[string]any{"name": "Acme", "slug": "acme"}), &orgOut)
	var provider struct {
		ProviderID  string `json:"providerId"`
		RedirectURI string `json:"redirectURI"`
	}
	c.MustOK(c.Post("/api/auth/sso/register", map[string]any{
		"providerId":     "acme",
		"issuer":         idp.Issuer,
		"domain":         "acme.example",
		"organizationId": orgOut.ID,
		"oidcConfig":     map[string]any{"clientId": "example-client", "clientSecret": "example-secret"},
	}), &provider)
	if provider.RedirectURI != exkit.DefaultBaseURL+"/api/auth/sso/callback/acme" {
		t.Fatalf("redirectURI = %s", provider.RedirectURI)
	}

	// Step 3: an employee signs in with their work email: sign-in → IdP → callback
	b := c.Fork()
	var start struct {
		URL string `json:"url"`
	}
	b.MustOK(b.Post("/api/auth/sign-in/sso", map[string]any{"email": "jane@acme.example", "callbackURL": "/dashboard"}), &start)
	if !strings.HasPrefix(start.URL, idp.AuthorizationEndpoint()) {
		t.Fatalf("authorization URL %s", start.URL)
	}
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Get(start.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cb := b.Get(strings.TrimPrefix(resp.Header.Get("Location"), c.BaseURL))
	if cb.Status != http.StatusFound || cb.Header.Get("Location") != "/dashboard" {
		t.Fatalf("callback %d %s", cb.Status, cb.Header.Get("Location"))
	}

	// Step 4: the employee is signed in and a member of Acme
	var me exkit.MeOutput
	b.MustOK(b.Get("/api/example/me"), &me.Body)
	if me.Body.Email != "jane@acme.example" {
		t.Fatalf("me = %+v", me.Body)
	}
	if r := b.Get("/api/auth/organization/list"); r.Status != http.StatusOK || !strings.Contains(string(r.Body), orgOut.ID) {
		t.Fatalf("organizations %d %s", r.Status, r.Body)
	}

	// Step 5: the SP metadata route answers for SAML providers only
	if r := c.Get("/api/auth/sso/saml2/sp/metadata?providerId=acme"); r.Status != http.StatusBadRequest {
		t.Fatalf("metadata of an OIDC provider: %d %s", r.Status, r.Body)
	}
}
