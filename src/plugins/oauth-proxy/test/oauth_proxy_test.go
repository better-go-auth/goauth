package test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	proxyservices "github.com/better-go-auth/goauth/src/plugins/oauth-proxy/services"
	socialconfig "github.com/better-go-auth/goauth/src/plugins/social/config"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
)

// decryptPackage decrypts the state package of a provider URL and the preview state it carries.
func decryptPackage(t *testing.T, providerURL string) (proxyservices.StatePackage, map[string]any) {
	t.Helper()
	u, _ := url.Parse(providerURL)
	plain, err := authcrypto.SymmetricDecrypt(secret, u.Query().Get("state"))
	if err != nil {
		t.Fatalf("state is not an encrypted package: %v", err)
	}
	var pkg proxyservices.StatePackage
	if err := json.Unmarshal([]byte(plain), &pkg); err != nil {
		t.Fatal(err)
	}
	inner, err := authcrypto.SymmetricDecrypt(secret, pkg.StateCookie)
	if err != nil {
		t.Fatalf("stateCookie: %v", err)
	}
	var state map[string]any
	if err := json.Unmarshal([]byte(inner), &state); err != nil {
		t.Fatal(err)
	}
	return pkg, state
}

// TestProxyFlow: the full preview flow for both state strategies: the preview's sign-in sends the provider to
// production's callback with an encrypted state package, production finishes the exchange and redirects to
// the preview's /oauth-proxy-callback with the encrypted profile, the preview signs the user in.
func TestProxyFlow(t *testing.T) {
	for _, strategy := range []socialconfig.StateStrategy{socialconfig.StateDatabase, socialconfig.StateCookie} {
		t.Run(string(strategy), func(t *testing.T) {
			p := newPair(t, strategy)
			// Step 1: sign-in on the preview
			res, providerURL := p.browser.signIn(p.preview, map[string]any{"callbackURL": "/dashboard"})
			pu, _ := url.Parse(providerURL)
			if got := pu.Query().Get("redirect_uri"); got != p.production.URL+"/api/auth/callback/fake" {
				t.Fatalf("redirect_uri = %s, want production's callback", got)
			}
			pkg, state := decryptPackage(t, providerURL)
			if !pkg.IsOAuthProxy || pkg.State == "" || len(pkg.State) != 32 {
				t.Fatalf("package = %+v", pkg)
			}
			if state["oauthState"] != pkg.State {
				t.Fatalf("package state %q does not match inner state %v", pkg.State, state["oauthState"])
			}
			wantCallback := p.preview.URL + "/api/auth/oauth-proxy-callback?callbackURL=%2Fdashboard"
			if state["callbackURL"] != wantCallback {
				t.Fatalf("callbackURL = %v, want %s", state["callbackURL"], wantCallback)
			}
			// better-auth only rewrites the body url; the Location header keeps the provider's raw state
			if loc, _ := url.Parse(res.location()); loc.Query().Get("state") != pkg.State {
				t.Fatalf("Location state = %q, want the original %q", loc.Query().Get("state"), pkg.State)
			}
			// Step 2: provider → production → preview
			callback := p.browser.authorize(providerURL)
			prodRes := p.browser.get(callback)
			if prodRes.Status != http.StatusFound {
				t.Fatalf("production callback: %d %s", prodRes.Status, prodRes.Body)
			}
			loc, _ := url.Parse(prodRes.location())
			if !strings.HasPrefix(prodRes.location(), p.preview.URL+"/api/auth/oauth-proxy-callback?callbackURL=%2Fdashboard&profile=") {
				t.Fatalf("production should redirect to the preview proxy callback, got %s", prodRes.location())
			}
			if len(prodRes.Header.Values("Set-Cookie")) != 0 {
				t.Fatalf("production must not set cookies: %v", prodRes.Header.Values("Set-Cookie"))
			}
			if n := countUsers(t, p.production); n != 0 {
				t.Fatalf("production created %d users", n)
			}
			// the profile is better-auth's payload
			plain, err := authcrypto.SymmetricDecrypt(secret, loc.Query().Get("profile"))
			if err != nil {
				t.Fatal(err)
			}
			var payload map[string]any
			_ = json.Unmarshal([]byte(plain), &payload)
			userInfo, _ := payload["userInfo"].(map[string]any)
			account, _ := payload["account"].(map[string]any)
			if userInfo["email"] != "fake.user@example.com" || account["providerId"] != "fake" || account["accountId"] != "fake-user-1" ||
				payload["callbackURL"] != "/dashboard" || payload["state"] != pkg.State || payload["disableSignUp"] != false {
				t.Fatalf("payload = %s", plain)
			}
			if _, ok := payload["timestamp"].(float64); !ok {
				t.Fatalf("timestamp missing: %s", plain)
			}
			// Step 3: the preview signs the user in and redirects to the original callback
			prevRes := p.browser.get(prodRes.location())
			if prevRes.Status != http.StatusFound || prevRes.location() != "/dashboard" {
				t.Fatalf("preview proxy callback: %d %s %s", prevRes.Status, prevRes.location(), prevRes.Body)
			}
			if prevRes.cookie("better-auth.session_token") == nil {
				t.Fatal("no session cookie on the preview")
			}
			if got := p.browser.session(p.preview); got != "fake.user@example.com" {
				t.Fatalf("preview session = %q", got)
			}
			if got := p.browser.session(p.production); got != "" {
				t.Fatalf("production session = %q, want none", got)
			}
			// the account carries the provider tokens, and the preview's OAuth state is consumed
			var acc models.Account
			if err := p.preview.DB.Where("provider_id = ?", "fake").First(&acc).Error; err != nil {
				t.Fatalf("account: %v", err)
			}
			if acc.AccountID != "fake-user-1" || acc.AccessToken == nil || *acc.AccessToken == "" {
				t.Fatalf("account = %+v", acc)
			}
			if strategy == socialconfig.StateDatabase {
				if n := countVerifications(t, p.preview); n != 0 {
					t.Fatalf("preview kept %d verification rows", n)
				}
			} else if ck := prevRes.cookie("better-auth.oauth_state"); ck == nil || ck.MaxAge >= 0 {
				t.Fatalf("oauth_state cookie should be expired, got %+v", ck)
			}
		})
	}
}

// TestProxyNewUserURL: a new user goes to newUserCallbackURL, a returning user to callbackURL.
func TestProxyNewUserURL(t *testing.T) {
	p := newPair(t, socialconfig.StateDatabase)
	body := func() map[string]any {
		return map[string]any{"callbackURL": "/dashboard", "newUserCallbackURL": "/welcome"}
	}
	_, res := p.flow(t, body())
	if res == nil || res.location() != "/welcome" {
		t.Fatalf("new user: %+v", res)
	}
	// a second sign-in from a fresh browser is a returning user
	p.browser = newBrowser(t)
	_, res = p.flow(t, body())
	if res == nil || res.location() != "/dashboard" {
		t.Fatalf("returning user: %+v", res)
	}
	if n := countUsers(t, p.preview); n != 1 {
		t.Fatalf("users = %d", n)
	}
}

// TestProxyDisableSignUp: the provider's disableImplicitSignUp travels in the payload; the preview refuses
// the new user with better-auth's signup_disabled code.
func TestProxyDisableSignUp(t *testing.T) {
	p := newPair(t, socialconfig.StateDatabase, func(prod, _ *deployOpts) {
		prod.provider = func(o *providers.GenericOptions) { o.DisableImplicitSignUp = true }
	})
	_, res := p.flow(t, map[string]any{"callbackURL": "/dashboard", "errorCallbackURL": "/oops"})
	if res == nil || res.Status != http.StatusFound || !strings.HasPrefix(res.location(), "/oops?") || errorOf(t, res.location()) != "signup_disabled" {
		t.Fatalf("expected /oops?error=signup_disabled, got %+v", res)
	}
	if n := countUsers(t, p.preview); n != 0 {
		t.Fatalf("users = %d", n)
	}
	// requestSignUp lifts disableImplicitSignUp
	p.browser = newBrowser(t)
	_, res = p.flow(t, map[string]any{"callbackURL": "/dashboard", "requestSignUp": true})
	if res == nil || res.location() != "/dashboard" {
		t.Fatalf("requestSignUp: %+v", res)
	}
}

// TestProxySkip: production itself and requests with x-skip-oauth-proxy use the normal flow.
func TestProxySkip(t *testing.T) {
	p := newPair(t, socialconfig.StateDatabase, func(prod, _ *deployOpts) {
		prod.proxy.ProductionURL = "" // production defaults to its own base URL
	})
	check := func(t *testing.T, d *deployment, headers ...string) {
		t.Helper()
		_, providerURL := p.browser.signIn(d, map[string]any{"callbackURL": "/home"}, headers...)
		u, _ := url.Parse(providerURL)
		if st := u.Query().Get("state"); len(st) != 32 {
			t.Fatalf("state should be the plain 32-char state, got %d chars", len(st))
		}
		if got := u.Query().Get("redirect_uri"); got != d.URL+"/api/auth/callback/fake" {
			t.Fatalf("redirect_uri = %s", got)
		}
		cb := p.browser.authorize(providerURL)
		res := p.browser.get(cb)
		if res.Status != http.StatusFound || res.location() != "/home" {
			t.Fatalf("callback: %d %s", res.Status, res.location())
		}
		if got := p.browser.session(d); got != "fake.user@example.com" {
			t.Fatalf("session = %q", got)
		}
	}
	t.Run("production", func(t *testing.T) { check(t, p.production) })
	t.Run("header", func(t *testing.T) { check(t, p.preview, proxyservices.SkipProxyHeader, "1") })
}

// TestProxyCurrentURL: CurrentURL replaces the request URL for the proxy callback origin.
func TestProxyCurrentURL(t *testing.T) {
	p := newPair(t, socialconfig.StateDatabase, func(_, prev *deployOpts) {
		prev.proxy.CurrentURL = "https://preview-123.example.com"
		prev.core = func(c *config.AuthConfig) { c.TrustedOrigins = []string{"https://preview-123.example.com"} }
	})
	_, providerURL := p.browser.signIn(p.preview, map[string]any{"callbackURL": "/x"})
	_, state := decryptPackage(t, providerURL)
	if state["callbackURL"] != "https://preview-123.example.com/api/auth/oauth-proxy-callback?callbackURL=%2Fx" {
		t.Fatalf("callbackURL = %v", state["callbackURL"])
	}
}

// TestProxyCallbackErrors: production's callback hook redirects with better-auth's codes.
func TestProxyCallbackErrors(t *testing.T) {
	p := newPair(t, socialconfig.StateDatabase)
	// a state package for a hand-made preview state
	pkgFor := func(t *testing.T, state string, data map[string]any) string {
		t.Helper()
		raw, _ := json.Marshal(data)
		inner, _ := authcrypto.SymmetricEncrypt(secret, string(raw))
		pkg, _ := json.Marshal(proxyservices.StatePackage{State: state, StateCookie: inner, IsOAuthProxy: true})
		enc, _ := authcrypto.SymmetricEncrypt(secret, string(pkg))
		return enc
	}
	data := map[string]any{
		"callbackURL": p.preview.URL + "/api/auth/oauth-proxy-callback?callbackURL=%2Fapp", "codeVerifier": "v",
		"errorURL": "/failed", "oauthState": "state-1", "expiresAt": time.Now().Add(time.Minute).UnixMilli(),
	}
	cb := func(path string, q url.Values) *response {
		return p.browser.get(p.production.URL + "/api/auth/callback/" + path + "?" + q.Encode())
	}
	cases := []struct {
		name, provider, code string
		q                    url.Values
	}{
		{"state mismatch", "fake", "state_mismatch", url.Values{"state": {pkgFor(t, "other-state", data)}, "code": {"c"}}},
		{"provider error", "fake", "access_denied", url.Values{"state": {pkgFor(t, "state-1", data)}, "error": {"access_denied"}}},
		{"no code", "fake", "no_code", url.Values{"state": {pkgFor(t, "state-1", data)}}},
		{"unknown provider", "nope", "oauth_provider_not_found", url.Values{"state": {pkgFor(t, "state-1", data)}, "code": {"c"}}},
		{"invalid code", "fake", "invalid_code", url.Values{"state": {pkgFor(t, "state-1", data)}, "code": {"bogus"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := cb(tc.provider, tc.q)
			if res.Status != http.StatusFound || !strings.HasPrefix(res.location(), "/failed?") || errorOf(t, res.location()) != tc.code {
				t.Fatalf("got %d %s, want /failed?error=%s", res.Status, res.location(), tc.code)
			}
		})
	}
	t.Run("default error URL", func(t *testing.T) {
		d := map[string]any{"callbackURL": "http://localhost/x", "codeVerifier": "v", "expiresAt": 1}
		res := cb("fake", url.Values{"state": {pkgFor(t, "s", d)}})
		if res.location() != p.production.URL+"/api/auth/error?error=no_code" {
			t.Fatalf("location = %s", res.location())
		}
	})
	t.Run("not a proxy state falls through", func(t *testing.T) {
		res := cb("fake", url.Values{"state": {"plain-state"}, "code": {"c"}})
		if res.Status != http.StatusFound || errorOf(t, res.location()) != "state_mismatch" ||
			!strings.HasPrefix(res.location(), p.production.URL+"/api/auth/error") {
			t.Fatalf("got %d %s", res.Status, res.location())
		}
	})
	t.Run("provider denies access in the real flow", func(t *testing.T) {
		p.fake.SetAuthorizeError("access_denied")
		defer p.fake.SetAuthorizeError("")
		_, providerURL := p.browser.signIn(p.preview, map[string]any{"callbackURL": "/app", "errorCallbackURL": p.preview.URL + "/oops"})
		res := p.browser.get(p.browser.authorize(providerURL))
		if !strings.HasPrefix(res.location(), p.preview.URL+"/oops?") || errorOf(t, res.location()) != "access_denied" {
			t.Fatalf("location = %s", res.location())
		}
	})
	t.Run("no email", func(t *testing.T) {
		p.fake.SetUser(socialtest.Profile{Sub: "no-mail"})
		defer p.fake.SetUser(socialtest.Profile{Sub: "fake-user-1", Email: "fake.user@example.com", EmailVerified: true, Name: "Fake User"})
		_, providerURL := p.browser.signIn(p.preview, map[string]any{"callbackURL": "/app", "errorCallbackURL": "/oops"})
		res := p.browser.get(p.browser.authorize(providerURL))
		if errorOf(t, res.location()) != "email_not_found" {
			t.Fatalf("location = %s", res.location())
		}
	})
}

// TestProxyCallbackEndpoint: GET /oauth-proxy-callback validation and error redirects.
func TestProxyCallbackEndpoint(t *testing.T) {
	p := newPair(t, socialconfig.StateDatabase)
	defaultErr := p.preview.URL + "/api/auth/error"
	enc := func(v any) string {
		raw, _ := json.Marshal(v)
		s, _ := authcrypto.SymmetricEncrypt(secret, string(raw))
		return s
	}
	now := float64(time.Now().UnixMilli())
	valid := func(mut func(m map[string]any)) map[string]any {
		m := map[string]any{
			"userInfo":    map[string]any{"id": "u-9", "email": "Nine@Example.com", "name": "Nine", "emailVerified": true},
			"account":     map[string]any{"providerId": "fake", "accountId": "u-9", "accessToken": "at", "scope": "openid,email"},
			"state":       "unknown-state",
			"callbackURL": "/done",
			"timestamp":   now,
		}
		if mut != nil {
			mut(m)
		}
		return m
	}
	get := func(q url.Values) *response {
		return newBrowser(t).get(p.preview.URL + "/api/auth/oauth-proxy-callback?" + q.Encode())
	}
	cases := []struct {
		name, profile, location string
	}{
		{"missing profile", "", defaultErr + "?error=missing_profile"},
		{"tampered profile", "deadbeef", defaultErr + "?error=invalid_profile"},
		{"not json", mustEncrypt(t, "not json"), defaultErr + "?error=invalid_payload"},
		{"missing fields", enc(map[string]any{"timestamp": now}), defaultErr + "?error=invalid_payload"},
		{"string timestamp", enc(valid(func(m map[string]any) { m["timestamp"] = "1" })), defaultErr + "?error=invalid_payload"},
		{"expired", enc(valid(func(m map[string]any) { m["timestamp"] = now - 61_000 })), defaultErr + "?error=payload_expired"},
		{"expired with errorURL", enc(valid(func(m map[string]any) {
			m["timestamp"] = now - 61_000
			m["errorURL"] = "/bad"
		})), "/bad?error=payload_expired"},
		{"from the future", enc(valid(func(m map[string]any) { m["timestamp"] = now + 20_000 })), defaultErr + "?error=payload_expired"},
		{"signup disabled", enc(valid(func(m map[string]any) { m["disableSignUp"] = true })), defaultErr + "?error=signup_disabled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := url.Values{"callbackURL": {"/done"}}
			if tc.profile != "" {
				q.Set("profile", tc.profile)
			}
			res := get(q)
			if res.Status != http.StatusFound || res.location() != tc.location {
				t.Fatalf("got %d %q, want %q (%s)", res.Status, res.location(), tc.location, res.Body)
			}
			if res.cookie("better-auth.session_token") != nil {
				t.Fatal("no session expected")
			}
		})
	}
	t.Run("untrusted callbackURL", func(t *testing.T) {
		res := get(url.Values{"callbackURL": {"https://evil.example.com"}, "profile": {enc(valid(nil))}})
		var e struct{ Code string }
		res.json(t, &e)
		if res.Status != http.StatusForbidden || e.Code != "INVALID_CALLBACK_URL" {
			t.Fatalf("got %d %s", res.Status, res.Body)
		}
	})
	t.Run("missing callbackURL", func(t *testing.T) {
		res := get(url.Values{"profile": {enc(valid(nil))}})
		if res.Status != http.StatusBadRequest {
			t.Fatalf("got %d %s", res.Status, res.Body)
		}
	})
	t.Run("valid payload signs in", func(t *testing.T) {
		b := newBrowser(t)
		res := b.get(p.preview.URL + "/api/auth/oauth-proxy-callback?" + url.Values{"callbackURL": {"/done"}, "profile": {enc(valid(nil))}}.Encode())
		if res.Status != http.StatusFound || res.location() != "/done" || res.cookie("better-auth.session_token") == nil {
			t.Fatalf("got %d %s", res.Status, res.location())
		}
		if got := b.session(p.preview); got != "nine@example.com" {
			t.Fatalf("session = %q", got)
		}
		var acc models.Account
		if err := p.preview.DB.Where("account_id = ?", "u-9").First(&acc).Error; err != nil || acc.Scope == nil || *acc.Scope != "openid,email" {
			t.Fatalf("account: %v %+v", err, acc)
		}
	})
	t.Run("custom secret", func(t *testing.T) {
		q := newPair(t, socialconfig.StateDatabase, func(_, prev *deployOpts) { prev.proxy.Secret = "another-proxy-secret-0123456789" })
		raw, _ := json.Marshal(valid(nil))
		withCore, _ := authcrypto.SymmetricEncrypt(secret, string(raw))
		res := newBrowser(t).get(q.preview.URL + "/api/auth/oauth-proxy-callback?" + url.Values{"callbackURL": {"/done"}, "profile": {withCore}}.Encode())
		if errorOf(t, res.location()) != "invalid_profile" {
			t.Fatalf("a profile encrypted with the auth secret must be refused, got %s", res.location())
		}
		withProxy, _ := authcrypto.SymmetricEncrypt("another-proxy-secret-0123456789", string(raw))
		res = newBrowser(t).get(q.preview.URL + "/api/auth/oauth-proxy-callback?" + url.Values{"callbackURL": {"/done"}, "profile": {withProxy}}.Encode())
		if res.location() != "/done" {
			t.Fatalf("location = %s", res.location())
		}
	})
	t.Run("onAPIError errorURL", func(t *testing.T) {
		q := newPair(t, socialconfig.StateDatabase, func(_, prev *deployOpts) {
			prev.core = func(c *config.AuthConfig) { c.OnAPIError.ErrorURL = "https://app.example.com/auth-error" }
		})
		res := newBrowser(t).get(q.preview.URL + "/api/auth/oauth-proxy-callback?callbackURL=%2Fdone")
		if res.location() != "https://app.example.com/auth-error?error=missing_profile" {
			t.Fatalf("location = %s", res.location())
		}
	})
}

func mustEncrypt(t *testing.T, s string) string {
	t.Helper()
	out, err := authcrypto.SymmetricEncrypt(secret, s)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestProxySameOriginCallbackRewrite: a regular callback on production that ends at production's own
// /oauth-proxy-callback goes straight to the inner callbackURL (the callback after hook).
func TestProxySameOriginCallbackRewrite(t *testing.T) {
	p := newPair(t, socialconfig.StateDatabase, func(prod, _ *deployOpts) { prod.proxy.ProductionURL = "" })
	inner := p.production.URL + "/api/auth/oauth-proxy-callback?callbackURL=%2Fhome"
	_, providerURL := p.browser.signIn(p.production, map[string]any{"callbackURL": inner})
	res := p.browser.get(p.browser.authorize(providerURL))
	if res.Status != http.StatusFound || res.location() != "/home" {
		t.Fatalf("got %d %s", res.Status, res.location())
	}
	if got := p.browser.session(p.production); got != "fake.user@example.com" {
		t.Fatalf("session = %q", got)
	}
}

// TestProxyDisabledRoute: DisabledPaths turns the endpoint off like any other route.
func TestProxyDisabledRoute(t *testing.T) {
	p := newPair(t, socialconfig.StateDatabase, func(_, prev *deployOpts) {
		prev.core = func(c *config.AuthConfig) { c.DisabledPaths = []string{"/oauth-proxy-callback"} }
	})
	if res := newBrowser(t).get(p.preview.URL + "/api/auth/oauth-proxy-callback?callbackURL=%2F"); res.Status != http.StatusNotFound {
		t.Fatalf("status = %d", res.Status)
	}
}
