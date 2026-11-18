package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
)

const (
	productionBase = "http://localhost:3000"
	previewBase    = "http://localhost:4000"
)

// fakeProvider is a generic OpenID Connect provider "fake" pointed at the in-process fake.
func fakeProvider(fake *socialtest.Provider) providers.Provider {
	return providers.Generic(providers.GenericOptions{
		ProviderID: "fake",
		Issuer:     fake.Issuer,
		ProviderOptions: providers.ProviderOptions{
			ClientID: fake.ClientID, ClientSecret: fake.ClientSecret,
			AuthorizationEndpoint: fake.AuthorizationEndpoint(), TokenEndpoint: fake.TokenEndpoint(),
			UserInfoEndpoint: fake.UserInfoEndpoint(), JWKSEndpoint: fake.JWKSEndpoint(),
		},
	})
}

func TestOAuthProxyFlow(t *testing.T) {
	// Step 0: a fake provider that only knows production's callback; it sends the browser to the production
	// test server
	fake := socialtest.New("client-id", "client-secret")
	t.Cleanup(fake.Close)
	fake.SetUser(socialtest.Profile{Sub: "gh-alice", Email: "alice@example.com", EmailVerified: true, Name: "Alice"})
	prodApp, err := newApp("", productionBase, productionBase, fakeProvider(fake))
	if err != nil {
		t.Fatal(err)
	}
	prod := exkit.StartTest(t, prodApp)
	fake.SetRedirectBase(prod.BaseURL)
	prevApp, err := newApp("", previewBase, productionBase, fakeProvider(fake))
	if err != nil {
		t.Fatal(err)
	}
	preview := exkit.StartTest(t, prevApp)

	// Step 1: sign-in on the preview: the provider is asked to call production back
	var start struct {
		URL string `json:"url"`
	}
	preview.MustOK(preview.Post("/api/auth/sign-in/social", map[string]any{
		"provider": "fake", "callbackURL": "/dashboard", "disableRedirect": true,
	}), &start)
	authURL, _ := url.Parse(start.URL)
	if got := authURL.Query().Get("redirect_uri"); got != productionBase+"/api/auth/callback/fake" {
		t.Fatalf("redirect_uri = %s", got)
	}

	// Step 2: the user approves at the provider, which redirects to production's callback
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Get(start.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	callback := resp.Header.Get("Location")
	if !strings.HasPrefix(callback, prod.BaseURL+"/api/auth/callback/fake?") {
		t.Fatalf("provider redirect: %s", callback)
	}

	// Step 3: production exchanges the code and sends the encrypted profile to the preview
	res := prod.Get(strings.TrimPrefix(callback, prod.BaseURL))
	proxyCallback := res.Header.Get("Location")
	if res.Status != http.StatusFound || !strings.HasPrefix(proxyCallback, preview.BaseURL+"/api/auth/oauth-proxy-callback?") {
		t.Fatalf("production callback: %d %s", res.Status, proxyCallback)
	}

	// Step 4: the preview signs Alice in and redirects to the original callbackURL
	res = preview.Get(strings.TrimPrefix(proxyCallback, preview.BaseURL))
	if res.Status != http.StatusFound || res.Header.Get("Location") != "/dashboard" {
		t.Fatalf("proxy callback: %d %s", res.Status, res.Header.Get("Location"))
	}
	var me exkit.MeOutput
	preview.MustOK(preview.Get("/api/example/me"), &me.Body)
	if me.Body.Email != "alice@example.com" {
		t.Fatalf("me = %+v", me.Body)
	}
	// production has no user and no session: it only relayed the sign-in
	if res := prod.Get("/api/example/me"); res.Status != http.StatusUnauthorized {
		t.Fatalf("production /me: %d", res.Status)
	}

	// Step 5: a stale or forged profile is refused with an error redirect
	res = preview.Fork().Get("/api/auth/oauth-proxy-callback?callbackURL=%2Fdashboard&profile=00ff")
	if loc := res.Header.Get("Location"); res.Status != http.StatusFound || !strings.Contains(loc, "error=invalid_profile") {
		t.Fatalf("forged profile: %d %s", res.Status, loc)
	}
}
