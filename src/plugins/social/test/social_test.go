package test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	socialconfig "github.com/better-go-auth/goauth/src/plugins/social/config"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
	"github.com/better-go-auth/goauth/src/plugins/social/services"
	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

// ─── /sign-in/social ─────────────────────────────────────────────────────────

func TestSignInSocial_AuthorizationURL(t *testing.T) {
	e := newEnv(t)

	// redirect branch: Location header + {url, redirect:true} + signed state cookie
	r := e.signIn(t, map[string]any{"callbackURL": baseURL + "/dashboard", "scopes": []string{"extra"}, "loginHint": "hint@example.com"})
	if r.Status != http.StatusOK {
		t.Fatalf("status %d: %s", r.Status, r.Body)
	}
	var body struct {
		URL      string `json:"url"`
		Redirect bool   `json:"redirect"`
	}
	r.JSON(t, &body)
	if !body.Redirect || body.URL == "" || r.Header.Get("Location") != body.URL {
		t.Fatalf("unexpected response: %s / Location %q", r.Body, r.Header.Get("Location"))
	}
	u, _ := url.Parse(body.URL)
	q := u.Query()
	if u.Scheme+"://"+u.Host+u.Path != e.fake.AuthorizationEndpoint() {
		t.Fatalf("wrong endpoint %s", body.URL)
	}
	checks := map[string]string{
		"response_type":         "code",
		"client_id":             clientID,
		"scope":                 "openid email profile extra",
		"redirect_uri":          baseURL + "/api/auth/callback/fake",
		"code_challenge_method": "S256",
		"login_hint":            "hint@example.com",
	}
	for k, want := range checks {
		if got := q.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if len(q.Get("state")) != 32 {
		t.Errorf("state length %d", len(q.Get("state")))
	}
	if len(q.Get("code_challenge")) != 43 {
		t.Errorf("code_challenge length %d", len(q.Get("code_challenge")))
	}
	ck := r.Cookie("better-auth.state")
	if ck == nil || ck.MaxAge != 300 || !ck.HttpOnly {
		t.Fatalf("missing/invalid state cookie: %+v", ck)
	}

	// the state is stored in a verification row keyed by the state, with the PKCE verifier matching the challenge
	var v models.Verification
	if err := e.s.DB.Where("identifier = ?", q.Get("state")).Take(&v).Error; err != nil {
		t.Fatalf("verification row: %v", err)
	}
	var data map[string]any
	_ = json.Unmarshal([]byte(v.Value), &data)
	if data["callbackURL"] != baseURL+"/dashboard" || data["oauthState"] != q.Get("state") {
		t.Fatalf("unexpected state data %s", v.Value)
	}
	if providers.CodeChallenge(data["codeVerifier"].(string)) != q.Get("code_challenge") || len(data["codeVerifier"].(string)) != 128 {
		t.Fatalf("code challenge does not match the stored verifier")
	}
	if time.Until(v.ExpiresAt) < 9*time.Minute {
		t.Fatalf("verification expires too early: %v", v.ExpiresAt)
	}

	// disableRedirect: no Location, redirect=false
	r = e.signIn(t, map[string]any{"disableRedirect": true})
	r.JSON(t, &body)
	if body.Redirect || r.Header.Get("Location") != "" {
		t.Fatalf("disableRedirect ignored: %s", r.Body)
	}
}

func TestSignInSocial_UnknownProvider(t *testing.T) {
	e := newEnv(t)
	r := e.signIn(t, map[string]any{"provider": "nope"})
	if r.Status != http.StatusNotFound || errCode(t, r) != "PROVIDER_NOT_FOUND" {
		t.Fatalf("expected 404 PROVIDER_NOT_FOUND, got %d %s", r.Status, r.Body)
	}
}

func TestSignInSocial_UntrustedURLs(t *testing.T) {
	e := newEnv(t)
	cases := map[string]string{
		"callbackURL":        "INVALID_CALLBACK_URL",
		"errorCallbackURL":   "INVALID_ERROR_CALLBACK_URL",
		"newUserCallbackURL": "INVALID_NEW_USER_CALLBACK_URL",
	}
	for field, code := range cases {
		r := e.signIn(t, map[string]any{field: "https://evil.example.com/steal"})
		if r.Status != http.StatusForbidden || errCode(t, r) != code {
			t.Errorf("%s: expected 403 %s, got %d %s", field, code, r.Status, r.Body)
		}
	}
	// relative paths are allowed
	if r := e.signIn(t, map[string]any{"callbackURL": "/dashboard", "disableRedirect": true}); r.Status != http.StatusOK {
		t.Fatalf("relative callbackURL rejected: %d %s", r.Status, r.Body)
	}
}

// ─── Callback: sign-up / sign-in ─────────────────────────────────────────────

func TestCallback_SignUpThenSignIn(t *testing.T) {
	e := newEnv(t)
	e.fake.SetUser(socialtest.Profile{Sub: "sub-1", Email: "Alice@Example.com", EmailVerified: true, Name: "Alice", Picture: "https://img.example.com/a.png"})

	// Step 1: first sign-in creates the user and redirects to newUserCallbackURL
	r := e.flow(t, map[string]any{"callbackURL": baseURL + "/dashboard", "newUserCallbackURL": baseURL + "/welcome"})
	if loc := location(t, r); loc != baseURL+"/welcome" {
		t.Fatalf("expected new user redirect, got %s", loc)
	}
	if sessionCookie(r) == nil || sessionCookie(r).Value == "" {
		t.Fatal("no session cookie on the callback redirect")
	}
	if ck := r.Cookie("better-auth.state"); ck == nil || ck.MaxAge >= 0 {
		t.Fatalf("state cookie not expired: %+v", ck)
	}
	// token request: PKCE verifier + client credentials + same redirect_uri
	tr := e.fake.LastTokenRequest()
	if tr.Get("code_verifier") == "" || tr.Get("client_secret") != clientSecret || tr.Get("redirect_uri") != baseURL+"/api/auth/callback/fake" {
		t.Fatalf("unexpected token request %v", tr)
	}

	u := userByEmail(t, e, "alice@example.com")
	if u == nil || !u.EmailVerified || u.Name != "Alice" || u.Image == nil || *u.Image != "https://img.example.com/a.png" {
		t.Fatalf("unexpected user %+v", u)
	}
	accs := accounts(t, e, "fake")
	if len(accs) != 1 {
		t.Fatalf("expected 1 account, got %d", len(accs))
	}
	a := accs[0]
	if a.UserID != u.ID || a.AccountID != "sub-1" || a.AccessToken == nil || !e.fake.IsAccessToken(*a.AccessToken) ||
		a.RefreshToken == nil || a.IDToken == nil || a.AccessTokenExpiresAt == nil || a.Scope == nil || *a.Scope != "openid,email,profile" {
		t.Fatalf("unexpected account %+v", a)
	}
	if d := time.Until(*a.AccessTokenExpiresAt); d < 50*time.Minute || d > 61*time.Minute {
		t.Fatalf("unexpected access token expiry %v", d)
	}
	if got := getSession(t, e); got != "alice@example.com" {
		t.Fatalf("get-session user %q", got)
	}

	// Step 2: second sign-in reuses the account, refreshes its tokens and goes to callbackURL
	firstAccess := *a.AccessToken
	r = e.flow(t, map[string]any{"callbackURL": baseURL + "/dashboard", "newUserCallbackURL": baseURL + "/welcome"})
	if loc := location(t, r); loc != baseURL+"/dashboard" {
		t.Fatalf("expected callbackURL redirect, got %s", loc)
	}
	accs = accounts(t, e, "fake")
	if len(accs) != 1 || *accs[0].AccessToken == firstAccess || !e.fake.IsAccessToken(*accs[0].AccessToken) {
		t.Fatalf("account not reused/refreshed: %+v", accs)
	}
	var count int64
	e.s.DB.Model(&models.User{}).Count(&count)
	if count != 1 {
		t.Fatalf("expected 1 user, got %d", count)
	}
}

func TestCallback_DefaultCallbackURLIsBaseURL(t *testing.T) {
	e := newEnv(t)
	r := e.flow(t, map[string]any{})
	if loc := location(t, r); loc != baseURL {
		t.Fatalf("expected redirect to baseURL, got %s", loc)
	}
}

func TestCallback_UpdateAccountOnSignInDisabled(t *testing.T) {
	e := newEnv(t, envOpts{social: func(_ *socialtest.Provider, c *socialconfig.SocialConfig) {
		c.UpdateAccountOnSignIn = socialconfig.Bool(false)
	}})
	location(t, e.flow(t, map[string]any{}))
	first := *accounts(t, e, "fake")[0].AccessToken
	location(t, e.flow(t, map[string]any{}))
	if got := *accounts(t, e, "fake")[0].AccessToken; got != first {
		t.Fatal("tokens updated although updateAccountOnSignIn=false")
	}
}

func TestCallback_OverrideUserInfoOnSignIn(t *testing.T) {
	e := newEnv(t, envOpts{social: func(fake *socialtest.Provider, c *socialconfig.SocialConfig) {
		c.Providers = []providers.Provider{genericFake(fake, func(o *providers.GenericOptions) { o.OverrideUserInfoOnSignIn = true })}
	}})
	e.fake.SetUser(socialtest.Profile{Sub: "s", Email: "o@example.com", EmailVerified: true, Name: "Old"})
	location(t, e.flow(t, map[string]any{}))
	e.fake.SetUser(socialtest.Profile{Sub: "s", Email: "o@example.com", EmailVerified: true, Name: "New Name"})
	location(t, e.flow(t, map[string]any{}))
	if u := userByEmail(t, e, "o@example.com"); u == nil || u.Name != "New Name" {
		t.Fatalf("user info not overridden: %+v", u)
	}
}

func TestCallback_MapProfileToUser(t *testing.T) {
	e := newEnv(t, envOpts{social: func(fake *socialtest.Provider, c *socialconfig.SocialConfig) {
		c.Providers = []providers.Provider{genericFake(fake, func(o *providers.GenericOptions) {
			o.MapProfileToUser = func(p map[string]any) map[string]any {
				return map[string]any{"name": "Mapped " + p["name"].(string), "firstName": "Mapped", "role": "admin"}
			}
		})}
	}})
	location(t, e.flow(t, map[string]any{}))
	u := userByEmail(t, e, "fake.user@example.com")
	if u == nil || u.Name != "Mapped Fake User" || u.FirstName != "Mapped" || u.Role == "admin" {
		t.Fatalf("unexpected mapped user %+v", u)
	}
}

// ─── Callback: state handling ────────────────────────────────────────────────

func TestCallback_StateErrors(t *testing.T) {
	t.Run("missing state param", func(t *testing.T) {
		e := newEnv(t)
		expectErrorRedirect(t, e.s.Get(t, "/api/auth/callback/fake?code=abc"), defaultErrorURL, "state_not_found")
	})
	t.Run("unknown state", func(t *testing.T) {
		e := newEnv(t)
		expectErrorRedirect(t, e.s.Get(t, "/api/auth/callback/fake?code=abc&state=bogus"), defaultErrorURL, "state_mismatch")
	})
	t.Run("missing state cookie redirects to errorCallbackURL", func(t *testing.T) {
		e := newEnv(t)
		cb := e.authorize(t, e.startFlow(t, map[string]any{"errorCallbackURL": baseURL + "/oops"}))
		// a different browser: no state cookie
		e.s.Jar = nil
		e.s.Client.Jar = nil
		expectErrorRedirect(t, e.s.Get(t, cb), baseURL+"/oops", "state_mismatch")
	})
	t.Run("forged state cookie", func(t *testing.T) {
		e := newEnv(t)
		cb := e.authorize(t, e.startFlow(t, map[string]any{}))
		e.s.Client.Jar = nil
		forged := map[string]string{"Cookie": "better-auth.state=" + url.QueryEscape("other.c2lnbmF0dXJl")}
		expectErrorRedirect(t, e.s.Get(t, cb, forged), defaultErrorURL, "state_mismatch")
	})
	t.Run("expired state", func(t *testing.T) {
		e := newEnv(t)
		authURL := e.startFlow(t, map[string]any{})
		u, _ := url.Parse(authURL)
		st := u.Query().Get("state")
		var v models.Verification
		e.s.DB.Where("identifier = ?", st).Take(&v)
		var data map[string]any
		_ = json.Unmarshal([]byte(v.Value), &data)
		data["expiresAt"] = time.Now().Add(-time.Minute).UnixMilli()
		raw, _ := json.Marshal(data)
		e.s.DB.Model(&models.Verification{}).Where("identifier = ?", st).Update("value", string(raw))
		r := e.s.Get(t, e.authorize(t, authURL))
		expectErrorRedirect(t, r, defaultErrorURL, "state_mismatch")
		if ck := r.Cookie("better-auth.state"); ck == nil || ck.MaxAge >= 0 {
			t.Fatalf("state cookie should be expired on an expired state")
		}
	})
	t.Run("reused state", func(t *testing.T) {
		e := newEnv(t)
		cb := e.authorize(t, e.startFlow(t, map[string]any{}))
		location(t, e.s.Get(t, cb))
		expectErrorRedirect(t, e.s.Get(t, cb), defaultErrorURL, "state_mismatch")
	})
	t.Run("skipStateCookieCheck", func(t *testing.T) {
		e := newEnv(t, envOpts{social: func(_ *socialtest.Provider, c *socialconfig.SocialConfig) { c.SkipStateCookieCheck = true }})
		cb := e.authorize(t, e.startFlow(t, map[string]any{"callbackURL": "/done"}))
		e.s.Client.Jar = nil
		if loc := location(t, e.s.Get(t, cb)); loc != "/done" {
			t.Fatalf("expected success without state cookie, got %s", loc)
		}
	})
	t.Run("custom ErrorURL", func(t *testing.T) {
		e := newEnv(t, envOpts{social: func(_ *socialtest.Provider, c *socialconfig.SocialConfig) { c.ErrorURL = baseURL + "/auth-error" }})
		expectErrorRedirect(t, e.s.Get(t, "/api/auth/callback/fake?state=x"), baseURL+"/auth-error", "state_mismatch")
	})
}

func TestCallback_CookieStateStrategy(t *testing.T) {
	e := newEnv(t, envOpts{social: func(_ *socialtest.Provider, c *socialconfig.SocialConfig) {
		c.StoreStateStrategy = socialconfig.StateCookie
	}})

	// sign-in sets the encrypted oauth_state cookie and stores nothing in the database
	r := e.signIn(t, map[string]any{"disableRedirect": true})
	ck := r.Cookie("better-auth.oauth_state")
	if ck == nil || ck.MaxAge != 600 || r.Cookie("better-auth.state") != nil {
		t.Fatalf("expected oauth_state cookie only: %v", r.Header.Values("Set-Cookie"))
	}
	var n int64
	e.s.DB.Model(&models.Verification{}).Count(&n)
	if n != 0 {
		t.Fatalf("cookie strategy wrote %d verification rows", n)
	}

	// full flow succeeds and clears the cookie
	r = e.flow(t, map[string]any{"callbackURL": "/home"})
	if location(t, r) != "/home" || sessionCookie(r) == nil {
		t.Fatalf("cookie strategy flow failed: %s", r.Header.Get("Location"))
	}
	if c := r.Cookie("better-auth.oauth_state"); c == nil || c.MaxAge >= 0 {
		t.Fatal("oauth_state cookie not cleared")
	}

	// tampered cookie → state_invalid; missing cookie → state_mismatch
	cb := e.authorize(t, e.startFlow(t, map[string]any{}))
	e.s.Client.Jar = nil
	expectErrorRedirect(t, e.s.Get(t, cb, map[string]string{"Cookie": "better-auth.oauth_state=deadbeef"}), defaultErrorURL, "state_invalid")
	expectErrorRedirect(t, e.s.Get(t, cb), defaultErrorURL, "state_mismatch")
}

// ─── Callback: provider / code errors ────────────────────────────────────────

func TestCallback_ProviderError(t *testing.T) {
	e := newEnv(t)
	e.fake.SetAuthorizeError("access_denied")
	r := e.flow(t, map[string]any{"errorCallbackURL": baseURL + "/oops?from=social"})
	loc := location(t, r)
	if loc != baseURL+"/oops?from=social&error=access_denied&error_description=The+user+denied+access" {
		t.Fatalf("unexpected error redirect %s", loc)
	}
}

func TestCallback_CodeAndProviderErrors(t *testing.T) {
	t.Run("no code", func(t *testing.T) {
		e := newEnv(t)
		cb := e.authorize(t, e.startFlow(t, map[string]any{}))
		u, _ := url.Parse(cb)
		q := u.Query()
		q.Del("code")
		u.RawQuery = q.Encode()
		expectErrorRedirect(t, e.s.Get(t, u.String()), defaultErrorURL, "no_code")
	})
	t.Run("invalid code", func(t *testing.T) {
		e := newEnv(t)
		cb := e.authorize(t, e.startFlow(t, map[string]any{}))
		u, _ := url.Parse(cb)
		q := u.Query()
		q.Set("code", "forged")
		u.RawQuery = q.Encode()
		expectErrorRedirect(t, e.s.Get(t, u.String()), defaultErrorURL, "invalid_code")
	})
	t.Run("provider not found", func(t *testing.T) {
		e := newEnv(t)
		cb := e.authorize(t, e.startFlow(t, map[string]any{}))
		expectErrorRedirect(t, e.s.Get(t, strings.Replace(cb, "/callback/fake", "/callback/unknown", 1)), defaultErrorURL, "oauth_provider_not_found")
	})
	t.Run("userinfo failure", func(t *testing.T) {
		e := newEnv(t, envOpts{social: func(fake *socialtest.Provider, c *socialconfig.SocialConfig) {
			c.Providers = []providers.Provider{genericFake(fake, func(o *providers.GenericOptions) { o.DisableIDTokenUserInfo = true })}
		}})
		e.fake.SetUserInfoFailure(true)
		expectErrorRedirect(t, e.flow(t, map[string]any{}), defaultErrorURL, "unable_to_get_user_info")
	})
	t.Run("missing email", func(t *testing.T) {
		e := newEnv(t)
		e.fake.SetUser(socialtest.Profile{Sub: "no-mail", EmailVerified: true, Name: "Nomail"})
		expectErrorRedirect(t, e.flow(t, map[string]any{}), defaultErrorURL, "email_not_found")
	})
	t.Run("wrong client secret", func(t *testing.T) {
		fakeSecret := envOpts{social: func(fake *socialtest.Provider, c *socialconfig.SocialConfig) {
			c.Providers = []providers.Provider{genericFake(fake, func(o *providers.GenericOptions) { o.ClientSecret = "wrong" })}
		}}
		e := newEnv(t, fakeSecret)
		expectErrorRedirect(t, e.flow(t, map[string]any{}), defaultErrorURL, "invalid_code")
	})
}

func TestCallback_FormPost(t *testing.T) {
	e := newEnv(t)
	form := url.Values{"code": {"the-code"}, "state": {"the-state"}, "user": {`{"name":{"firstName":"A"}}`}}
	req, _ := http.NewRequest(http.MethodPost, e.s.URL+"/api/auth/callback/fake?state=query-state", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := e.noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	want := baseURL + "/api/auth/callback/fake?code=the-code&state=query-state&user=" + url.QueryEscape(`{"name":{"firstName":"A"}}`)
	if got := resp.Header.Get("Location"); got != want {
		t.Fatalf("Location = %s\nwant %s", got, want)
	}
}

// ─── Account linking on sign-in ──────────────────────────────────────────────

func TestImplicitLinking(t *testing.T) {
	t.Run("links to a verified local user", func(t *testing.T) {
		e := newEnv(t)
		local := createUser(t, e, "fake.user@example.com", true)
		r := e.flow(t, map[string]any{"callbackURL": "/app", "newUserCallbackURL": "/new"})
		if location(t, r) != "/app" || sessionCookie(r) == nil {
			t.Fatalf("expected sign-in into the existing user, got %s", r.Header.Get("Location"))
		}
		accs := accounts(t, e, "fake")
		if len(accs) != 1 || accs[0].UserID != local.ID {
			t.Fatalf("account not linked to the local user: %+v", accs)
		}
	})
	t.Run("refuses an unverified local user", func(t *testing.T) {
		e := newEnv(t)
		createUser(t, e, "fake.user@example.com", false)
		expectErrorRedirect(t, e.flow(t, map[string]any{}), defaultErrorURL, "account_not_linked")
		if len(accounts(t, e, "fake")) != 0 {
			t.Fatal("account was linked")
		}
	})
	t.Run("requireLocalEmailVerified=false links and verifies", func(t *testing.T) {
		e := newEnv(t, envOpts{social: func(_ *socialtest.Provider, c *socialconfig.SocialConfig) {
			c.AccountLinking.RequireLocalEmailVerified = socialconfig.Bool(false)
		}})
		createUser(t, e, "fake.user@example.com", false)
		location(t, e.flow(t, map[string]any{}))
		if u := userByEmail(t, e, "fake.user@example.com"); u == nil || !u.EmailVerified {
			t.Fatalf("email should be verified after linking: %+v", u)
		}
	})
	t.Run("unverified provider email needs a trusted provider", func(t *testing.T) {
		e := newEnv(t)
		createUser(t, e, "fake.user@example.com", true)
		e.fake.SetUser(socialtest.Profile{Sub: "u2", Email: "fake.user@example.com", EmailVerified: false})
		expectErrorRedirect(t, e.flow(t, map[string]any{}), defaultErrorURL, "account_not_linked")

		trusted := newEnv(t, envOpts{social: func(_ *socialtest.Provider, c *socialconfig.SocialConfig) {
			c.AccountLinking.TrustedProviders = []string{"fake"}
		}})
		createUser(t, trusted, "fake.user@example.com", true)
		trusted.fake.SetUser(socialtest.Profile{Sub: "u2", Email: "fake.user@example.com", EmailVerified: false})
		location(t, trusted.flow(t, map[string]any{}))
		if len(accounts(t, trusted, "fake")) != 1 {
			t.Fatal("trusted provider not linked")
		}
	})
	t.Run("disableImplicitLinking", func(t *testing.T) {
		e := newEnv(t, envOpts{social: func(_ *socialtest.Provider, c *socialconfig.SocialConfig) {
			c.AccountLinking.DisableImplicitLinking = true
		}})
		createUser(t, e, "fake.user@example.com", true)
		expectErrorRedirect(t, e.flow(t, map[string]any{}), defaultErrorURL, "account_not_linked")
	})
	t.Run("linking disabled", func(t *testing.T) {
		e := newEnv(t, envOpts{social: func(_ *socialtest.Provider, c *socialconfig.SocialConfig) {
			c.AccountLinking.Enabled = socialconfig.Bool(false)
		}})
		createUser(t, e, "fake.user@example.com", true)
		expectErrorRedirect(t, e.flow(t, map[string]any{}), defaultErrorURL, "account_not_linked")
	})
	t.Run("updateUserInfoOnLink", func(t *testing.T) {
		e := newEnv(t, envOpts{social: func(_ *socialtest.Provider, c *socialconfig.SocialConfig) {
			c.AccountLinking.UpdateUserInfoOnLink = true
		}})
		createUser(t, e, "fake.user@example.com", true)
		location(t, e.flow(t, map[string]any{}))
		if u := userByEmail(t, e, "fake.user@example.com"); u == nil || u.Name != "Fake User" {
			t.Fatalf("profile not copied on link: %+v", u)
		}
	})
}

func TestSignUpPolicies(t *testing.T) {
	t.Run("disableSignUp", func(t *testing.T) {
		e := newEnv(t, envOpts{social: func(fake *socialtest.Provider, c *socialconfig.SocialConfig) {
			c.Providers = []providers.Provider{genericFake(fake, func(o *providers.GenericOptions) { o.DisableSignUp = true })}
		}})
		expectErrorRedirect(t, e.flow(t, map[string]any{}), defaultErrorURL, "signup_disabled")
		if userByEmail(t, e, "fake.user@example.com") != nil {
			t.Fatal("user created although sign-up is disabled")
		}
		// existing users can still sign in
		createUser(t, e, "fake.user@example.com", true)
		location(t, e.flow(t, map[string]any{}))
	})
	t.Run("disableImplicitSignUp needs requestSignUp", func(t *testing.T) {
		e := newEnv(t, envOpts{social: func(fake *socialtest.Provider, c *socialconfig.SocialConfig) {
			c.Providers = []providers.Provider{genericFake(fake, func(o *providers.GenericOptions) { o.DisableImplicitSignUp = true })}
		}})
		expectErrorRedirect(t, e.flow(t, map[string]any{}), defaultErrorURL, "signup_disabled")
		if loc := location(t, e.flow(t, map[string]any{"requestSignUp": true, "callbackURL": "/ok"})); loc != "/ok" {
			t.Fatalf("requestSignUp sign-up failed: %s", loc)
		}
	})
	t.Run("sendOnSignUp verification email for unverified provider email", func(t *testing.T) {
		var sentTo, link string
		e := newEnv(t, envOpts{core: func(c *config.AuthConfig) {
			c.EmailVerification.SendOnSignUp = socialconfig.Bool(true)
			c.EmailVerification.SendVerificationEmail = func(d config.EmailVerificationData, _ *http.Request) error {
				sentTo, link = d.User.Email, d.URL
				return nil
			}
		}})
		e.fake.SetUser(socialtest.Profile{Sub: "nv", Email: "nv@example.com", EmailVerified: false})
		location(t, e.flow(t, map[string]any{"callbackURL": "/after"}))
		if sentTo != "nv@example.com" || !strings.HasPrefix(link, baseURL+"/api/auth/verify-email?token=") || !strings.HasSuffix(link, "&callbackURL=%2Fafter") {
			t.Fatalf("verification email not sent: %q %q", sentTo, link)
		}
	})
}

// ─── /link-social ────────────────────────────────────────────────────────────

func linkFlow(t *testing.T, e *env, body map[string]any) *compattest.Response {
	t.Helper()
	if _, ok := body["provider"]; !ok {
		body["provider"] = "fake"
	}
	body["disableRedirect"] = true
	r := e.s.Post(t, "/api/auth/link-social", body)
	if r.Status != http.StatusOK {
		t.Fatalf("link-social: %d %s", r.Status, r.Body)
	}
	var out struct {
		URL      string `json:"url"`
		Redirect bool   `json:"redirect"`
	}
	r.JSON(t, &out)
	return e.s.Get(t, e.authorize(t, out.URL))
}

func TestLinkSocial(t *testing.T) {
	t.Run("requires a session", func(t *testing.T) {
		e := newEnv(t)
		r := e.s.Post(t, "/api/auth/link-social", map[string]any{"provider": "fake"})
		if r.Status != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d %s", r.Status, r.Body)
		}
	})
	t.Run("links the provider account to the signed-in user", func(t *testing.T) {
		e := newEnv(t)
		signUpEmail(t, e, "fake.user@example.com")
		user := userByEmail(t, e, "fake.user@example.com")
		r := linkFlow(t, e, map[string]any{"callbackURL": "/settings"})
		if location(t, r) != "/settings" || sessionCookie(r) != nil {
			t.Fatalf("unexpected link redirect %s", r.Header.Get("Location"))
		}
		accs := accounts(t, e, "fake")
		if len(accs) != 1 || accs[0].UserID != user.ID {
			t.Fatalf("account not linked: %+v", accs)
		}
		// list-accounts (core) shows both accounts
		la := e.s.Get(t, "/api/auth/list-accounts")
		if !strings.Contains(string(la.Body), `"providerId":"fake"`) || !strings.Contains(string(la.Body), `"providerId":"credential"`) {
			t.Fatalf("list-accounts: %s", la.Body)
		}
		// linking again just refreshes the tokens
		location(t, linkFlow(t, e, map[string]any{"callbackURL": "/settings"}))
		if len(accounts(t, e, "fake")) != 1 {
			t.Fatal("duplicate account")
		}
	})
	t.Run("different email is refused unless allowed", func(t *testing.T) {
		e := newEnv(t)
		signUpEmail(t, e, "someone@example.com")
		expectErrorRedirect(t, linkFlow(t, e, map[string]any{}), defaultErrorURL, "email_doesn't_match")

		allowed := newEnv(t, envOpts{social: func(_ *socialtest.Provider, c *socialconfig.SocialConfig) {
			c.AccountLinking.AllowDifferentEmails = true
		}})
		signUpEmail(t, allowed, "someone@example.com")
		location(t, linkFlow(t, allowed, map[string]any{"callbackURL": "/ok"}))
		if len(accounts(t, allowed, "fake")) != 1 {
			t.Fatal("not linked with allowDifferentEmails")
		}
	})
	t.Run("unverified provider email is refused", func(t *testing.T) {
		e := newEnv(t)
		signUpEmail(t, e, "fake.user@example.com")
		e.fake.SetUser(socialtest.Profile{Sub: "x", Email: "fake.user@example.com", EmailVerified: false})
		expectErrorRedirect(t, linkFlow(t, e, map[string]any{}), defaultErrorURL, "unable_to_link_account")
	})
	t.Run("account linked to another user", func(t *testing.T) {
		e := newEnv(t, envOpts{social: func(_ *socialtest.Provider, c *socialconfig.SocialConfig) {
			c.AccountLinking.AllowDifferentEmails = true
		}})
		// user A signs up through the provider
		location(t, e.flow(t, map[string]any{}))
		// user B tries to link the same provider account
		e.s.Client.Jar = nil
		e.s.Client.Jar, _ = newJar()
		signUpEmail(t, e, "b@example.com")
		expectErrorRedirect(t, linkFlow(t, e, map[string]any{"errorCallbackURL": baseURL + "/link-error"}), baseURL+"/link-error", "account_already_linked_to_different_user")
	})
}

// ─── id_token sign-in ────────────────────────────────────────────────────────

func TestIDTokenSignIn(t *testing.T) {
	e := newEnv(t, envOpts{social: func(fake *socialtest.Provider, c *socialconfig.SocialConfig) {
		noJWKS := genericFake(fake, func(o *providers.GenericOptions) { o.ProviderID = "nojwks"; o.JWKSEndpoint = "" })
		c.Providers = append(c.Providers, noJWKS)
	}})
	prof := socialtest.Profile{Sub: "idt-1", Email: "idt@example.com", EmailVerified: true, Name: "Id Token"}

	t.Run("valid token signs up and returns the session", func(t *testing.T) {
		tok := e.fake.SignIDToken(prof, "n-1", nil)
		r := e.signIn(t, map[string]any{"idToken": map[string]any{"token": tok, "nonce": "n-1", "accessToken": "at-direct"}})
		if r.Status != http.StatusOK {
			t.Fatalf("status %d: %s", r.Status, r.Body)
		}
		var out struct {
			Redirect bool    `json:"redirect"`
			Token    string  `json:"token"`
			URL      *string `json:"url"`
			User     struct {
				Email         string `json:"email"`
				EmailVerified bool   `json:"emailVerified"`
			} `json:"user"`
		}
		r.JSON(t, &out)
		if out.Redirect || out.Token == "" || out.URL != nil || out.User.Email != "idt@example.com" || !out.User.EmailVerified {
			t.Fatalf("unexpected body %s", r.Body)
		}
		if sessionCookie(r) == nil {
			t.Fatal("no session cookie")
		}
		accs := accounts(t, e, "fake")
		if len(accs) != 1 || accs[0].AccountID != "idt-1" || accs[0].AccessToken == nil || *accs[0].AccessToken != "at-direct" {
			t.Fatalf("unexpected account %+v", accs)
		}
	})
	t.Run("invalid signature", func(t *testing.T) {
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		tok := e.fake.SignIDTokenWithKey(other, prof, "", nil)
		r := e.signIn(t, map[string]any{"idToken": map[string]any{"token": tok}})
		if r.Status != http.StatusUnauthorized || errCode(t, r) != "INVALID_TOKEN" {
			t.Fatalf("expected 401 INVALID_TOKEN, got %d %s", r.Status, r.Body)
		}
	})
	t.Run("wrong nonce / audience / issuer / expired", func(t *testing.T) {
		bad := map[string]string{
			"nonce":    e.fake.SignIDToken(prof, "n-1", nil),
			"audience": e.fake.SignIDToken(prof, "", map[string]any{"aud": "someone-else"}),
			"issuer":   e.fake.SignIDToken(prof, "", map[string]any{"iss": "https://evil.example.com"}),
			"expired":  e.fake.SignIDToken(prof, "", map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}),
			"too old":  e.fake.SignIDToken(prof, "", map[string]any{"iat": time.Now().Add(-2 * time.Hour).Unix()}),
		}
		for name, tok := range bad {
			r := e.signIn(t, map[string]any{"idToken": map[string]any{"token": tok, "nonce": "other"}})
			if r.Status != http.StatusUnauthorized || errCode(t, r) != "INVALID_TOKEN" {
				t.Errorf("%s: expected 401 INVALID_TOKEN, got %d %s", name, r.Status, r.Body)
			}
		}
	})
	t.Run("provider without id_token support", func(t *testing.T) {
		r := e.signIn(t, map[string]any{"provider": "nojwks", "idToken": map[string]any{"token": e.fake.SignIDToken(prof, "", nil)}})
		if r.Status != http.StatusNotFound || errCode(t, r) != "ID_TOKEN_NOT_SUPPORTED" {
			t.Fatalf("expected 404 ID_TOKEN_NOT_SUPPORTED, got %d %s", r.Status, r.Body)
		}
	})
	t.Run("token without email", func(t *testing.T) {
		tok := e.fake.SignIDToken(socialtest.Profile{Sub: "nomail"}, "", nil)
		r := e.signIn(t, map[string]any{"idToken": map[string]any{"token": tok}})
		if r.Status != http.StatusUnauthorized || errCode(t, r) != "USER_EMAIL_NOT_FOUND" {
			t.Fatalf("expected USER_EMAIL_NOT_FOUND, got %d %s", r.Status, r.Body)
		}
	})
	t.Run("link error is OAUTH_LINK_ERROR", func(t *testing.T) {
		createUser(t, e, "unverified-local@example.com", false)
		tok := e.fake.SignIDToken(socialtest.Profile{Sub: "ul", Email: "unverified-local@example.com", EmailVerified: true}, "", nil)
		r := e.signIn(t, map[string]any{"idToken": map[string]any{"token": tok}})
		var out struct {
			Code, Message string
		}
		r.JSON(t, &out)
		if r.Status != http.StatusUnauthorized || out.Code != "OAUTH_LINK_ERROR" || out.Message != "account not linked" {
			t.Fatalf("expected OAUTH_LINK_ERROR, got %d %s", r.Status, r.Body)
		}
	})
}

func TestIDTokenSignIn_Google(t *testing.T) {
	e := newEnv(t, envOpts{social: func(fake *socialtest.Provider, c *socialconfig.SocialConfig) {
		fake.Issuer = "https://accounts.google.com"
		c.Providers = []providers.Provider{providers.Google(providers.GoogleOptions{ProviderOptions: providers.ProviderOptions{
			ClientID: clientID, ClientSecret: clientSecret, JWKSEndpoint: fake.JWKSEndpoint(),
		}})}
	}})
	prof := socialtest.Profile{Sub: "g-1", Email: "g@example.com", EmailVerified: true, Name: "G User", Picture: "https://img/g.png"}
	r := e.signIn(t, map[string]any{"provider": "google", "idToken": map[string]any{"token": e.fake.SignIDToken(prof, "", nil)}})
	if r.Status != http.StatusOK {
		t.Fatalf("google id token sign-in: %d %s", r.Status, r.Body)
	}
	if u := userByEmail(t, e, "g@example.com"); u == nil || u.Image == nil || *u.Image != "https://img/g.png" {
		t.Fatalf("unexpected google user %+v", u)
	}
	// wrong issuer for google
	tok := e.fake.SignIDToken(prof, "", map[string]any{"iss": "https://other"})
	if r := e.signIn(t, map[string]any{"provider": "google", "idToken": map[string]any{"token": tok}}); r.Status != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong google issuer, got %d", r.Status)
	}
}

func TestLinkSocial_IDToken(t *testing.T) {
	e := newEnv(t)
	signUpEmail(t, e, "fake.user@example.com")
	prof := socialtest.Profile{Sub: "lk", Email: "fake.user@example.com", EmailVerified: true}
	body := map[string]any{"provider": "fake", "idToken": map[string]any{"token": e.fake.SignIDToken(prof, "", nil), "scopes": []string{"a", "b"}}}
	r := e.s.Post(t, "/api/auth/link-social", body)
	if r.Status != http.StatusOK || !strings.Contains(string(r.Body), `"status":true`) {
		t.Fatalf("link-social idToken: %d %s", r.Status, r.Body)
	}
	accs := accounts(t, e, "fake")
	if len(accs) != 1 || accs[0].Scope == nil || *accs[0].Scope != "a,b" {
		t.Fatalf("unexpected linked account %+v", accs)
	}
	// idempotent
	if r := e.s.Post(t, "/api/auth/link-social", body); r.Status != http.StatusOK {
		t.Fatalf("second link: %d %s", r.Status, r.Body)
	}
	// different email
	other := map[string]any{"provider": "fake", "idToken": map[string]any{"token": e.fake.SignIDToken(socialtest.Profile{Sub: "lk2", Email: "x@example.com", EmailVerified: true}, "", nil)}}
	if r := e.s.Post(t, "/api/auth/link-social", other); r.Status != http.StatusUnauthorized || errCode(t, r) != "LINKING_DIFFERENT_EMAILS_NOT_ALLOWED" {
		t.Fatalf("expected LINKING_DIFFERENT_EMAILS_NOT_ALLOWED, got %d %s", r.Status, r.Body)
	}
	// unverified email
	unv := map[string]any{"provider": "fake", "idToken": map[string]any{"token": e.fake.SignIDToken(socialtest.Profile{Sub: "lk3", Email: "fake.user@example.com"}, "", nil)}}
	if r := e.s.Post(t, "/api/auth/link-social", unv); r.Status != http.StatusUnauthorized || errCode(t, r) != "LINKING_NOT_ALLOWED" {
		t.Fatalf("expected LINKING_NOT_ALLOWED, got %d %s", r.Status, r.Body)
	}
}

// ─── Account tokens ──────────────────────────────────────────────────────────

func TestAccountTokens(t *testing.T) {
	e := newEnv(t)
	e.fake.SetUser(socialtest.Profile{Sub: "tok-1", Email: "tok@example.com", EmailVerified: true, Name: "Tok"})
	// tokens that expire within the 5s refresh window
	e.fake.SetExpiresIn(2)
	location(t, e.flow(t, map[string]any{}))
	stored := accounts(t, e, "fake")[0]

	t.Run("unauthenticated", func(t *testing.T) {
		anon := &http.Client{}
		req, _ := http.NewRequest(http.MethodPost, e.s.URL+"/api/auth/get-access-token", strings.NewReader(`{"providerId":"fake"}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := anon.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", resp.StatusCode)
		}
	})
	t.Run("unknown provider", func(t *testing.T) {
		r := e.s.Post(t, "/api/auth/get-access-token", map[string]any{"providerId": "nope"})
		if r.Status != http.StatusBadRequest || errCode(t, r) != "PROVIDER_NOT_SUPPORTED" {
			t.Fatalf("expected PROVIDER_NOT_SUPPORTED, got %d %s", r.Status, r.Body)
		}
	})
	t.Run("get-access-token refreshes an expiring token", func(t *testing.T) {
		e.fake.SetExpiresIn(3600)
		r := e.s.Post(t, "/api/auth/get-access-token", map[string]any{"providerId": "fake"})
		if r.Status != http.StatusOK {
			t.Fatalf("get-access-token: %d %s", r.Status, r.Body)
		}
		var out struct {
			AccessToken          string   `json:"accessToken"`
			AccessTokenExpiresAt string   `json:"accessTokenExpiresAt"`
			Scopes               []string `json:"scopes"`
			IDToken              string   `json:"idToken"`
		}
		r.JSON(t, &out)
		if e.fake.RefreshCount() != 1 || out.AccessToken == *stored.AccessToken || !e.fake.IsAccessToken(out.AccessToken) {
			t.Fatalf("token not refreshed: %s", r.Body)
		}
		if len(out.Scopes) != 3 || out.IDToken == "" || out.AccessTokenExpiresAt == "" {
			t.Fatalf("unexpected body %s", r.Body)
		}
		acc := accounts(t, e, "fake")[0]
		if *acc.AccessToken != out.AccessToken || time.Until(*acc.AccessTokenExpiresAt) < 50*time.Minute || *acc.RefreshToken == *stored.RefreshToken {
			t.Fatalf("refreshed tokens not persisted: %+v", acc)
		}
		// a fresh token is returned as is
		r2 := e.s.Post(t, "/api/auth/get-access-token", map[string]any{"providerId": "fake", "accountId": "tok-1"})
		var out2 struct {
			AccessToken string `json:"accessToken"`
		}
		r2.JSON(t, &out2)
		if out2.AccessToken != out.AccessToken || e.fake.RefreshCount() != 1 {
			t.Fatalf("unexpected second refresh")
		}
		// unknown account
		r3 := e.s.Post(t, "/api/auth/get-access-token", map[string]any{"providerId": "fake", "accountId": "other"})
		if r3.Status != http.StatusBadRequest || errCode(t, r3) != "ACCOUNT_NOT_FOUND" {
			t.Fatalf("expected ACCOUNT_NOT_FOUND, got %d %s", r3.Status, r3.Body)
		}
	})
	t.Run("refresh-token", func(t *testing.T) {
		before := accounts(t, e, "fake")[0]
		r := e.s.Post(t, "/api/auth/refresh-token", map[string]any{"providerId": "fake"})
		if r.Status != http.StatusOK {
			t.Fatalf("refresh-token: %d %s", r.Status, r.Body)
		}
		var out struct {
			AccessToken, RefreshToken, ProviderID, AccountID, AccessTokenExpiresAt string
			Scope                                                                  *string
		}
		r.JSON(t, &out)
		if out.AccessToken == *before.AccessToken || out.RefreshToken == *before.RefreshToken || out.ProviderID != "fake" || out.AccountID != "tok-1" ||
			out.Scope == nil || *out.Scope != "openid,email,profile" || out.AccessTokenExpiresAt == "" {
			t.Fatalf("unexpected refresh body %s", r.Body)
		}
		after := accounts(t, e, "fake")[0]
		if *after.AccessToken != out.AccessToken || *after.RefreshToken != out.RefreshToken {
			t.Fatal("refresh not persisted")
		}
		if r := e.s.Post(t, "/api/auth/refresh-token", map[string]any{"providerId": "nope"}); errCode(t, r) != "PROVIDER_NOT_SUPPORTED" {
			t.Fatalf("expected PROVIDER_NOT_SUPPORTED, got %s", r.Body)
		}
	})
	t.Run("refresh-token without refresh token", func(t *testing.T) {
		e.s.DB.Model(&models.Account{}).Where("provider_id = ?", "fake").Update("refresh_token", nil)
		r := e.s.Post(t, "/api/auth/refresh-token", map[string]any{"providerId": "fake"})
		if r.Status != http.StatusBadRequest || errCode(t, r) != "REFRESH_TOKEN_NOT_FOUND" {
			t.Fatalf("expected REFRESH_TOKEN_NOT_FOUND, got %d %s", r.Status, r.Body)
		}
	})
	t.Run("account-info", func(t *testing.T) {
		r := e.s.Get(t, "/api/auth/account-info?accountId=tok-1")
		if r.Status != http.StatusOK {
			t.Fatalf("account-info: %d %s", r.Status, r.Body)
		}
		var out struct {
			User struct {
				ID, Email, Name string
				EmailVerified   bool
			}
			Data map[string]any
		}
		r.JSON(t, &out)
		if out.User.ID != "tok-1" || out.User.Email != "tok@example.com" || !out.User.EmailVerified || out.Data["sub"] != "tok-1" {
			t.Fatalf("unexpected account-info %s", r.Body)
		}
		if r := e.s.Get(t, "/api/auth/account-info"); r.Status != http.StatusBadRequest || errCode(t, r) != "ACCOUNT_NOT_FOUND" {
			t.Fatalf("expected ACCOUNT_NOT_FOUND without accountId, got %d %s", r.Status, r.Body)
		}
	})
}

func TestEncryptOAuthTokens(t *testing.T) {
	e := newEnv(t, envOpts{social: func(_ *socialtest.Provider, c *socialconfig.SocialConfig) { c.EncryptOAuthTokens = true }})
	location(t, e.flow(t, map[string]any{}))
	acc := accounts(t, e, "fake")[0]
	if e.fake.IsAccessToken(*acc.AccessToken) {
		t.Fatal("access token stored in clear text")
	}
	plain, err := authcrypto.SymmetricDecrypt(compattest.TestSecret, *acc.AccessToken)
	if err != nil || !e.fake.IsAccessToken(plain) {
		t.Fatalf("stored token does not decrypt to the issued token: %v", err)
	}
	rt, err := authcrypto.SymmetricDecrypt(compattest.TestSecret, *acc.RefreshToken)
	if err != nil || !strings.HasPrefix(rt, "rt-") {
		t.Fatalf("refresh token not encrypted: %v", err)
	}
	// the API returns the clear token
	r := e.s.Post(t, "/api/auth/get-access-token", map[string]any{"providerId": "fake"})
	var out struct {
		AccessToken string `json:"accessToken"`
	}
	r.JSON(t, &out)
	if out.AccessToken != plain {
		t.Fatalf("get-access-token returned %q, want %q", out.AccessToken, plain)
	}
	// refresh-token decrypts the stored refresh token and stores the new ones encrypted
	r = e.s.Post(t, "/api/auth/refresh-token", map[string]any{"providerId": "fake"})
	if r.Status != http.StatusOK {
		t.Fatalf("refresh-token: %d %s", r.Status, r.Body)
	}
	acc = accounts(t, e, "fake")[0]
	if e.fake.IsAccessToken(*acc.AccessToken) || strings.HasPrefix(*acc.RefreshToken, "rt-") {
		t.Fatal("refreshed tokens stored in clear text")
	}
}

// ─── Misc ────────────────────────────────────────────────────────────────────

func TestDisabledOps(t *testing.T) {
	e := newEnv(t, envOpts{core: func(c *config.AuthConfig) { c.DisabledPaths = append(c.DisabledPaths, "/link-social") }})
	if r := e.s.Post(t, "/api/auth/link-social", map[string]any{"provider": "fake"}); r.Status != http.StatusNotFound && r.Status != http.StatusMethodNotAllowed {
		t.Fatalf("disabled path still served: %d", r.Status)
	}
}

func TestStateErrorType(t *testing.T) {
	var err error = &services.StateError{Code: "state_mismatch", Message: "m"}
	if err.Error() != "m" {
		t.Fatal("StateError message")
	}
}
