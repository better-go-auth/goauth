package test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/models"
	genericoauth "github.com/better-go-auth/goauth/src/plugins/generic-oauth"
	goconfig "github.com/better-go-auth/goauth/src/plugins/generic-oauth/config"
	gproviders "github.com/better-go-auth/goauth/src/plugins/generic-oauth/providers"
	"github.com/better-go-auth/goauth/src/plugins/social"
	socialconfig "github.com/better-go-auth/goauth/src/plugins/social/config"
	socialproviders "github.com/better-go-auth/goauth/src/plugins/social/providers"
	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

// ─── POST /sign-in/oauth2 ────────────────────────────────────────────────────

func TestSignIn_AuthorizationURL(t *testing.T) {
	e := newEnv(t, envOpts{provider: func(_ *socialtest.Provider, pc *goconfig.ProviderConfig) {
		pc.Prompt = "consent"
		pc.AccessType = "offline"
		pc.ResponseMode = "query"
		pc.AuthorizationURLParams = map[string]string{"audience": "api"}
		pc.AuthorizationURLParamsFunc = func(context.Context) map[string]string { return map[string]string{"tenant": "t1"} }
	}})

	// Step 1: {url, redirect:true} + the signed state cookie, no Location header (better-auth's client redirects)
	r := e.signIn(t, map[string]any{"callbackURL": baseURL + "/dashboard", "scopes": []string{"extra"}})
	if r.Status != http.StatusOK {
		t.Fatalf("status %d: %s", r.Status, r.Body)
	}
	var body redirectBody
	r.JSON(t, &body)
	if !body.Redirect || body.URL == "" || r.Header.Get("Location") != "" {
		t.Fatalf("unexpected response: %s / Location %q", r.Body, r.Header.Get("Location"))
	}
	if ck := r.Cookie("better-auth.state"); ck == nil || ck.MaxAge != 300 {
		t.Fatalf("missing state cookie: %+v", ck)
	}

	// Step 2: the authorization request
	u, _ := url.Parse(body.URL)
	q := u.Query()
	if u.Scheme+"://"+u.Host+u.Path != e.fake.AuthorizationEndpoint() {
		t.Fatalf("wrong endpoint %s", body.URL)
	}
	for k, want := range map[string]string{
		"response_type":         "code",
		"client_id":             clientID,
		"scope":                 "extra openid email profile",
		"redirect_uri":          callbackURI,
		"code_challenge_method": "S256",
		"prompt":                "consent",
		"access_type":           "offline",
		"response_mode":         "query",
		"audience":              "api",
		"tenant":                "t1",
	} {
		if got := q.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if len(q.Get("state")) != 32 || len(q.Get("code_challenge")) != 43 {
		t.Errorf("state / code_challenge: %q %q", q.Get("state"), q.Get("code_challenge"))
	}

	// Step 3: the state row stores the PKCE verifier and the callback URL
	var v models.Verification
	if err := e.s.DB.Where("identifier = ?", q.Get("state")).Take(&v).Error; err != nil {
		t.Fatalf("verification row: %v", err)
	}
	var data map[string]any
	_ = json.Unmarshal([]byte(v.Value), &data)
	if data["callbackURL"] != baseURL+"/dashboard" || socialproviders.CodeChallenge(data["codeVerifier"].(string)) != q.Get("code_challenge") {
		t.Fatalf("unexpected state data %s", v.Value)
	}

	// Step 4: disableRedirect
	r = e.signIn(t, map[string]any{"disableRedirect": true})
	r.JSON(t, &body)
	if body.Redirect {
		t.Fatalf("disableRedirect ignored: %s", r.Body)
	}
}

func TestSignIn_NoPKCE(t *testing.T) {
	e := newEnv(t, envOpts{provider: func(_ *socialtest.Provider, pc *goconfig.ProviderConfig) { pc.PKCE = false }})
	u, _ := url.Parse(e.startFlow(t, map[string]any{}))
	if u.Query().Get("code_challenge") != "" || u.Query().Get("code_challenge_method") != "" {
		t.Fatalf("PKCE sent although disabled: %s", u)
	}
	// the flow still works and no code_verifier reaches the token endpoint
	location(t, e.s.Get(t, e.authorize(t, u.String())))
	if e.fake.LastTokenRequest().Has("code_verifier") {
		t.Fatal("code_verifier sent although PKCE is disabled")
	}
}

func TestSignIn_Errors(t *testing.T) {
	e := newEnv(t, envOpts{plugin: func(_ *socialtest.Provider, cfg *goconfig.Config) {
		cfg.Providers = append(cfg.Providers, goconfig.ProviderConfig{ProviderID: "broken", ClientID: clientID})
	}})
	// unknown provider: 400 with better-auth's "No config found for provider <id>"
	r := e.signIn(t, map[string]any{"providerId": "nope"})
	if code, msg := errBody(t, r); r.Status != http.StatusBadRequest || code != "PROVIDER_CONFIG_NOT_FOUND" || msg != "No config found for provider nope" {
		t.Fatalf("unknown provider: %d %s", r.Status, r.Body)
	}
	// no endpoints
	r = e.signIn(t, map[string]any{"providerId": "broken"})
	if code, _ := errBody(t, r); r.Status != http.StatusBadRequest || code != "INVALID_OAUTH_CONFIGURATION" {
		t.Fatalf("broken provider: %d %s", r.Status, r.Body)
	}
	// untrusted redirect targets
	for field, code := range map[string]string{
		"callbackURL":        "INVALID_CALLBACK_URL",
		"errorCallbackURL":   "INVALID_ERROR_CALLBACK_URL",
		"newUserCallbackURL": "INVALID_NEW_USER_CALLBACK_URL",
	} {
		r := e.signIn(t, map[string]any{field: "https://evil.example.com/steal"})
		if got, _ := errBody(t, r); r.Status != http.StatusForbidden || got != code {
			t.Errorf("%s: expected 403 %s, got %d %s", field, code, r.Status, r.Body)
		}
	}
}

// ─── Callback: sign-up / sign-in ─────────────────────────────────────────────

func TestCallback_SignUpThenSignIn(t *testing.T) {
	e := newEnv(t)
	e.fake.SetUser(socialtest.Profile{Sub: "sub-1", Email: "Alice@Example.com", EmailVerified: true, Name: "Alice", Picture: "https://img.example.com/a.png"})

	// Step 1: first sign-in creates the user and goes to newUserCallbackURL
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
	// the PKCE verifier reached the token endpoint (the fake verifies it against the challenge)
	if len(e.fake.LastTokenRequest().Get("code_verifier")) != 128 || e.fake.LastTokenRequest().Get("redirect_uri") != callbackURI {
		t.Fatalf("token request: %v", e.fake.LastTokenRequest())
	}
	u := userByEmail(t, e, "alice@example.com")
	if u == nil || u.Name != "Alice" || !u.EmailVerified || u.Image == nil || *u.Image != "https://img.example.com/a.png" {
		t.Fatalf("unexpected user %+v", u)
	}
	accs := accounts(t, e, "fake")
	if len(accs) != 1 || accs[0].AccountID != "sub-1" || accs[0].UserID != u.ID || accs[0].AccessToken == nil || accs[0].Scope == nil || *accs[0].Scope != "openid,email,profile" {
		t.Fatalf("unexpected accounts %+v", accs)
	}

	// Step 2: the session works
	if r := e.s.Get(t, "/api/auth/get-session"); !strings.Contains(string(r.Body), "alice@example.com") {
		t.Fatalf("get-session: %s", r.Body)
	}

	// Step 3: second sign-in goes to callbackURL and refreshes the stored tokens
	old := *accs[0].AccessToken
	r = e.flow(t, map[string]any{"callbackURL": baseURL + "/dashboard", "newUserCallbackURL": baseURL + "/welcome"})
	if loc := location(t, r); loc != baseURL+"/dashboard" {
		t.Fatalf("expected existing user redirect, got %s", loc)
	}
	accs = accounts(t, e, "fake")
	if len(accs) != 1 || *accs[0].AccessToken == old {
		t.Fatalf("tokens not refreshed: %+v", accs)
	}
}

func TestCallback_DefaultCallbackURLIsBaseURL(t *testing.T) {
	e := newEnv(t)
	if loc := location(t, e.flow(t, map[string]any{})); loc != baseURL {
		t.Fatalf("expected %s, got %s", baseURL, loc)
	}
}

func TestCallback_UserInfoEndpoint(t *testing.T) {
	e := newEnv(t)
	// without id_token the profile comes from the userinfo endpoint
	e.fake.SetIssueIDToken(false)
	e.fake.SetUser(socialtest.Profile{Sub: "ui-1", Email: "ui@example.com", EmailVerified: true, Name: "User Info"})
	location(t, e.flow(t, map[string]any{}))
	if u := userByEmail(t, e, "ui@example.com"); u == nil || u.Name != "User Info" {
		t.Fatalf("user not created from userinfo: %+v", u)
	}
	if accs := accounts(t, e, "fake"); len(accs) != 1 || accs[0].AccountID != "ui-1" {
		t.Fatalf("accounts: %+v", accs)
	}
}

func TestCallback_Discovery(t *testing.T) {
	e := newEnv(t, envOpts{provider: func(fake *socialtest.Provider, pc *goconfig.ProviderConfig) {
		pc.AuthorizationURL, pc.TokenURL, pc.UserInfoURL = "", "", ""
		pc.DiscoveryURL = fake.DiscoveryURL()
		pc.DiscoveryHeaders = map[string]string{"X-Discovery": "yes"}
	}})
	e.fake.SetIssueIDToken(false)

	// Step 1: the endpoints come from the discovery document
	authURL := e.startFlow(t, map[string]any{"callbackURL": "/home"})
	if !strings.HasPrefix(authURL, e.fake.AuthorizationEndpoint()+"?") {
		t.Fatalf("authorization URL not discovered: %s", authURL)
	}
	if e.fake.LastDiscoveryHeader().Get("X-Discovery") != "yes" {
		t.Fatal("discoveryHeaders not sent")
	}
	// Step 2: token + userinfo endpoints discovered too; the issuer (discovery) is accepted in `iss`
	e.fake.SetAuthorizeIssuer(e.fake.Issuer)
	if loc := location(t, e.s.Get(t, e.authorize(t, authURL))); loc != "/home" {
		t.Fatalf("discovery flow failed: %s", loc)
	}
	// Step 3: the document is cached across endpoints and requests
	if n := e.fake.DiscoveryCount(); n != 1 {
		t.Fatalf("discovery fetched %d times, want 1 (cached)", n)
	}
}

func TestCallback_IssuerValidation(t *testing.T) {
	t.Run("mismatch", func(t *testing.T) {
		e := newEnv(t, envOpts{provider: func(fake *socialtest.Provider, pc *goconfig.ProviderConfig) { pc.Issuer = fake.Issuer }})
		e.fake.SetAuthorizeIssuer("https://evil.example.com")
		expectErrorRedirect(t, e.flow(t, map[string]any{"errorCallbackURL": "/oops"}), "/oops", "issuer_mismatch")
	})
	t.Run("missing but required", func(t *testing.T) {
		e := newEnv(t, envOpts{provider: func(fake *socialtest.Provider, pc *goconfig.ProviderConfig) {
			pc.Issuer = fake.Issuer
			pc.RequireIssuerValidation = true
		}})
		expectErrorRedirect(t, e.flow(t, map[string]any{}), defaultErrorURL, "issuer_missing")
	})
	t.Run("missing and optional", func(t *testing.T) {
		e := newEnv(t, envOpts{provider: func(fake *socialtest.Provider, pc *goconfig.ProviderConfig) { pc.Issuer = fake.Issuer }})
		if loc := location(t, e.flow(t, map[string]any{"callbackURL": "/ok"})); loc != "/ok" {
			t.Fatalf("got %s", loc)
		}
	})
}

func TestCallback_TokenAuthentication(t *testing.T) {
	t.Run("basic", func(t *testing.T) {
		e := newEnv(t, envOpts{provider: func(_ *socialtest.Provider, pc *goconfig.ProviderConfig) {
			pc.Authentication = socialproviders.AuthBasic
			pc.AuthorizationHeaders = map[string]string{"X-Custom": "1"}
			pc.TokenURLParams = map[string]string{"resource": "api://x"}
		}})
		e.fake.SetTokenAuthMethod("basic")
		location(t, e.flow(t, map[string]any{"callbackURL": "/ok"}))
		h := e.fake.LastTokenHeader()
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+clientSecret))
		if h.Get("Authorization") != want || h.Get("X-Custom") != "1" {
			t.Fatalf("token request headers: %v", h)
		}
		form := e.fake.LastTokenRequest()
		if form.Has("client_secret") || form.Get("resource") != "api://x" {
			t.Fatalf("token request form: %v", form)
		}
		if len(accounts(t, e, "fake")) != 1 {
			t.Fatal("no account")
		}
	})
	t.Run("post", func(t *testing.T) {
		e := newEnv(t)
		e.fake.SetTokenAuthMethod("post")
		location(t, e.flow(t, map[string]any{"callbackURL": "/ok"}))
		if form := e.fake.LastTokenRequest(); form.Get("client_id") != clientID || form.Get("client_secret") != clientSecret {
			t.Fatalf("token request form: %v", form)
		}
	})
	t.Run("wrong method fails the exchange", func(t *testing.T) {
		e := newEnv(t)
		e.fake.SetTokenAuthMethod("basic")
		expectErrorRedirect(t, e.flow(t, map[string]any{"errorCallbackURL": baseURL + "/oops"}), baseURL+"/oops", "oauth_code_verification_failed")
	})
}

func TestCallback_ProviderErrors(t *testing.T) {
	t.Run("provider error goes to the default error URL", func(t *testing.T) {
		e := newEnv(t)
		e.fake.SetAuthorizeError("access_denied")
		q := expectErrorRedirect(t, e.flow(t, map[string]any{"errorCallbackURL": baseURL + "/oops"}), defaultErrorURL, "access_denied")
		if q.Get("error_description") != "The user denied access" {
			t.Fatalf("error_description: %v", q)
		}
	})
	t.Run("missing code", func(t *testing.T) {
		e := newEnv(t)
		expectErrorRedirect(t, e.s.Get(t, "/api/auth/oauth2/callback/fake?state=x"), defaultErrorURL, "oAuth_code_missing")
	})
	t.Run("unknown provider", func(t *testing.T) {
		e := newEnv(t)
		r := e.s.Get(t, "/api/auth/oauth2/callback/nope?code=c&state=x")
		if code, msg := errBody(t, r); r.Status != http.StatusBadRequest || code != "PROVIDER_CONFIG_NOT_FOUND" || msg != "No config found for provider nope" {
			t.Fatalf("unknown provider: %d %s", r.Status, r.Body)
		}
	})
	t.Run("invalid client secret", func(t *testing.T) {
		e := newEnv(t, envOpts{provider: func(_ *socialtest.Provider, pc *goconfig.ProviderConfig) { pc.ClientSecret = "wrong" }})
		expectErrorRedirect(t, e.flow(t, map[string]any{"errorCallbackURL": baseURL + "/oops"}), baseURL+"/oops", "oauth_code_verification_failed")
	})
	t.Run("user info missing", func(t *testing.T) {
		e := newEnv(t)
		e.fake.SetIssueIDToken(false)
		e.fake.SetUserInfoFailure(true)
		expectErrorRedirect(t, e.flow(t, map[string]any{}), defaultErrorURL, "user_info_is_missing")
	})
	t.Run("email missing", func(t *testing.T) {
		e := newEnv(t)
		e.fake.SetUser(socialtest.Profile{Sub: "no-mail", Name: "No Mail"})
		expectErrorRedirect(t, e.flow(t, map[string]any{}), defaultErrorURL, "email_is_missing")
	})
	t.Run("name missing", func(t *testing.T) {
		e := newEnv(t)
		e.fake.SetUser(socialtest.Profile{Sub: "no-name", Email: "noname@example.com", EmailVerified: true})
		expectErrorRedirect(t, e.flow(t, map[string]any{}), defaultErrorURL, "name_is_missing")
	})
}

func TestCallback_InvalidState(t *testing.T) {
	e := newEnv(t)
	// forged state: no verification row
	expectErrorRedirect(t, e.s.Get(t, "/api/auth/oauth2/callback/fake?code=c&state=forged"), defaultErrorURL, "state_mismatch")
	// a real state completed in another browser (no signed state cookie) goes to the flow's errorCallbackURL
	cb := e.authorize(t, e.startFlow(t, map[string]any{"errorCallbackURL": baseURL + "/oops"}))
	freshBrowser(e)
	expectErrorRedirect(t, e.s.Get(t, cb), baseURL+"/oops", "state_mismatch")
	// a consumed state is single use
	cb = e.authorize(t, e.startFlow(t, map[string]any{"callbackURL": "/ok"}))
	if loc := location(t, e.s.Get(t, cb)); loc != "/ok" {
		t.Fatalf("flow: %s", loc)
	}
	expectErrorRedirect(t, e.s.Get(t, cb), defaultErrorURL, "state_mismatch")
}

func TestCallback_CookieStateStrategy(t *testing.T) {
	e := newEnv(t, envOpts{plugin: func(_ *socialtest.Provider, cfg *goconfig.Config) { cfg.StoreStateStrategy = socialconfig.StateCookie }})
	r := e.signIn(t, map[string]any{"callbackURL": "/x", "disableRedirect": true})
	if r.Cookie("better-auth.oauth_state") == nil {
		t.Fatalf("no oauth_state cookie: %v", r.Header)
	}
	var body redirectBody
	r.JSON(t, &body)
	if loc := location(t, e.s.Get(t, e.authorize(t, body.URL))); loc != "/x" {
		t.Fatalf("cookie strategy flow: %s", loc)
	}
}

// ─── Account linking and sign-up policies ────────────────────────────────────

func TestImplicitLinking(t *testing.T) {
	t.Run("verified local user + verified provider email links", func(t *testing.T) {
		e := newEnv(t)
		u := createUser(t, e, "fake.user@example.com", true)
		if loc := location(t, e.flow(t, map[string]any{"callbackURL": "/in", "newUserCallbackURL": "/new"})); loc != "/in" {
			t.Fatalf("expected existing-user redirect, got %s", loc)
		}
		if accs := accounts(t, e, "fake"); len(accs) != 1 || accs[0].UserID != u.ID {
			t.Fatalf("not linked: %+v", accs)
		}
	})
	t.Run("unverified local user is not linked", func(t *testing.T) {
		e := newEnv(t)
		createUser(t, e, "fake.user@example.com", false)
		expectErrorRedirect(t, e.flow(t, map[string]any{}), defaultErrorURL, "account_not_linked")
	})
	t.Run("unverified provider email is not linked unless trusted", func(t *testing.T) {
		e := newEnv(t)
		createUser(t, e, "fake.user@example.com", true)
		e.fake.SetUser(socialtest.Profile{Sub: "s", Email: "fake.user@example.com", EmailVerified: false, Name: "F"})
		expectErrorRedirect(t, e.flow(t, map[string]any{}), defaultErrorURL, "account_not_linked")

		trusted := newEnv(t, envOpts{plugin: func(_ *socialtest.Provider, cfg *goconfig.Config) {
			cfg.AccountLinking.TrustedProviders = []string{"fake"}
		}})
		createUser(t, trusted, "fake.user@example.com", true)
		trusted.fake.SetUser(socialtest.Profile{Sub: "s", Email: "fake.user@example.com", EmailVerified: false, Name: "F"})
		location(t, trusted.flow(t, map[string]any{}))
		if len(accounts(t, trusted, "fake")) != 1 {
			t.Fatal("trusted provider not linked")
		}
	})
	t.Run("implicit linking disabled", func(t *testing.T) {
		e := newEnv(t, envOpts{plugin: func(_ *socialtest.Provider, cfg *goconfig.Config) {
			cfg.AccountLinking.DisableImplicitLinking = true
		}})
		createUser(t, e, "fake.user@example.com", true)
		expectErrorRedirect(t, e.flow(t, map[string]any{}), defaultErrorURL, "account_not_linked")
	})
}

func TestSignUpPolicies(t *testing.T) {
	t.Run("disableImplicitSignUp requires requestSignUp", func(t *testing.T) {
		e := newEnv(t, envOpts{provider: func(_ *socialtest.Provider, pc *goconfig.ProviderConfig) { pc.DisableImplicitSignUp = true }})
		expectErrorRedirect(t, e.flow(t, map[string]any{"errorCallbackURL": "/err"}), "/err", "signup_disabled")
		if loc := location(t, e.flow(t, map[string]any{"requestSignUp": true, "newUserCallbackURL": "/new"})); loc != "/new" {
			t.Fatalf("requestSignUp did not sign up: %s", loc)
		}
		// existing users still sign in without requestSignUp
		if loc := location(t, e.flow(t, map[string]any{"callbackURL": "/in"})); loc != "/in" {
			t.Fatalf("existing user: %s", loc)
		}
	})
	t.Run("disableSignUp wins over requestSignUp", func(t *testing.T) {
		e := newEnv(t, envOpts{provider: func(_ *socialtest.Provider, pc *goconfig.ProviderConfig) { pc.DisableSignUp = true }})
		expectErrorRedirect(t, e.flow(t, map[string]any{"requestSignUp": true}), defaultErrorURL, "signup_disabled")
		if userByEmail(t, e, "fake.user@example.com") != nil {
			t.Fatal("user created although sign-up is disabled")
		}
	})
}

// ─── POST /oauth2/link ───────────────────────────────────────────────────────

func TestLink(t *testing.T) {
	t.Run("requires a session", func(t *testing.T) {
		e := newEnv(t)
		r := e.s.Post(t, "/api/auth/oauth2/link", map[string]any{"providerId": "fake", "callbackURL": "/x"})
		if r.Status != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d %s", r.Status, r.Body)
		}
	})
	t.Run("unknown provider", func(t *testing.T) {
		e := newEnv(t)
		signUpEmail(t, e, "a@example.com")
		r := e.s.Post(t, "/api/auth/oauth2/link", map[string]any{"providerId": "nope", "callbackURL": "/x"})
		if code, _ := errBody(t, r); r.Status != http.StatusNotFound || code != "PROVIDER_NOT_FOUND" {
			t.Fatalf("expected 404 PROVIDER_NOT_FOUND, got %d %s", r.Status, r.Body)
		}
	})
	t.Run("links the provider account to the session user", func(t *testing.T) {
		e := newEnv(t)
		signUpEmail(t, e, "fake.user@example.com")
		user := userByEmail(t, e, "fake.user@example.com")
		r := e.s.Post(t, "/api/auth/oauth2/link", map[string]any{"providerId": "fake", "callbackURL": "/settings", "scopes": []string{"only"}})
		var body redirectBody
		r.JSON(t, &body)
		u, _ := url.Parse(body.URL)
		if !body.Redirect || u.Query().Get("scope") != "only" || u.Query().Get("redirect_uri") != callbackURI {
			t.Fatalf("link URL: %s", r.Body)
		}
		cb := e.s.Get(t, e.authorize(t, body.URL))
		if location(t, cb) != "/settings" || sessionCookie(cb) != nil {
			t.Fatalf("unexpected link redirect %s", cb.Header.Get("Location"))
		}
		if accs := accounts(t, e, "fake"); len(accs) != 1 || accs[0].UserID != user.ID {
			t.Fatalf("account not linked: %+v", accs)
		}
		// linking again refreshes the tokens without duplicating the account
		location(t, e.linkFlow(t, map[string]any{}))
		if len(accounts(t, e, "fake")) != 1 {
			t.Fatal("duplicate account")
		}
	})
	t.Run("unverified provider email still links (generic-oauth has no trust check)", func(t *testing.T) {
		e := newEnv(t)
		signUpEmail(t, e, "fake.user@example.com")
		e.fake.SetUser(socialtest.Profile{Sub: "u", Email: "fake.user@example.com", EmailVerified: false, Name: "U"})
		if loc := location(t, e.linkFlow(t, map[string]any{})); loc != "/settings" {
			t.Fatalf("got %s", loc)
		}
	})
	t.Run("different email is refused unless allowed", func(t *testing.T) {
		e := newEnv(t)
		signUpEmail(t, e, "someone@example.com")
		expectErrorRedirect(t, e.linkFlow(t, map[string]any{"errorCallbackURL": "/link-error"}), "/link-error", "email_doesn't_match")

		allowed := newEnv(t, envOpts{plugin: func(_ *socialtest.Provider, cfg *goconfig.Config) {
			cfg.AccountLinking.AllowDifferentEmails = true
		}})
		signUpEmail(t, allowed, "someone@example.com")
		location(t, allowed.linkFlow(t, map[string]any{}))
		if len(accounts(t, allowed, "fake")) != 1 {
			t.Fatal("not linked with allowDifferentEmails")
		}
	})
	t.Run("account linked to another user", func(t *testing.T) {
		e := newEnv(t, envOpts{plugin: func(_ *socialtest.Provider, cfg *goconfig.Config) {
			cfg.AccountLinking.AllowDifferentEmails = true
		}})
		location(t, e.flow(t, map[string]any{}))
		freshBrowser(e)
		signUpEmail(t, e, "b@example.com")
		expectErrorRedirect(t, e.linkFlow(t, map[string]any{}), defaultErrorURL, "account_already_linked_to_different_user")
	})
	t.Run("updateUserInfoOnLink", func(t *testing.T) {
		e := newEnv(t, envOpts{plugin: func(_ *socialtest.Provider, cfg *goconfig.Config) {
			cfg.AccountLinking.UpdateUserInfoOnLink = true
		}})
		signUpEmail(t, e, "fake.user@example.com")
		location(t, e.linkFlow(t, map[string]any{}))
		if u := userByEmail(t, e, "fake.user@example.com"); u.Name != "Fake User" {
			t.Fatalf("profile not synced: %q", u.Name)
		}
	})
}

// ─── Overrides ───────────────────────────────────────────────────────────────

func TestMapProfileToUser(t *testing.T) {
	e := newEnv(t, envOpts{provider: func(_ *socialtest.Provider, pc *goconfig.ProviderConfig) {
		pc.MapProfileToUser = func(profile map[string]any) map[string]any {
			return map[string]any{"name": "Mapped " + gproviders.StringOf(profile["name"]), "firstName": "Map", "id": "mapped-" + gproviders.StringOf(profile["sub"])}
		}
	}})
	location(t, e.flow(t, map[string]any{}))
	u := userByEmail(t, e, "fake.user@example.com")
	if u == nil || u.Name != "Mapped Fake User" || u.FirstName != "Map" {
		t.Fatalf("mapProfileToUser not applied: %+v", u)
	}
	if accs := accounts(t, e, "fake"); len(accs) != 1 || accs[0].AccountID != "mapped-fake-user-1" {
		t.Fatalf("mapped id not used: %+v", accs)
	}
}

func TestGetUserInfoAndGetTokenOverrides(t *testing.T) {
	var gotCode, gotVerifier string
	e := newEnv(t, envOpts{provider: func(_ *socialtest.Provider, pc *goconfig.ProviderConfig) {
		pc.TokenURL = "http://127.0.0.1:1/unused" // getToken replaces the token endpoint
		pc.AccessTokenExpiresIn = time.Hour
		pc.GetToken = func(_ context.Context, in goconfig.GetTokenInput) (*socialproviders.OAuth2Tokens, error) {
			gotCode, gotVerifier = in.Code, in.CodeVerifier
			if in.RedirectURI != callbackURI {
				return nil, errors.New("bad redirect uri")
			}
			return &socialproviders.OAuth2Tokens{AccessToken: "custom-at", Scopes: []string{"a", "b"}}, nil
		}
		pc.GetUserInfo = func(_ context.Context, tokens socialproviders.OAuth2Tokens) (map[string]any, error) {
			if tokens.AccessToken != "custom-at" {
				return nil, nil
			}
			return map[string]any{"id": 42, "name": "Custom", "email": "CUSTOM@example.com", "emailVerified": true}, nil
		}
	}})
	if loc := location(t, e.flow(t, map[string]any{"callbackURL": "/c"})); loc != "/c" {
		t.Fatalf("got %s", loc)
	}
	if !strings.HasPrefix(gotCode, "code-") || len(gotVerifier) != 128 {
		t.Fatalf("getToken input: %q %q", gotCode, gotVerifier)
	}
	u := userByEmail(t, e, "custom@example.com")
	if u == nil || u.Name != "Custom" || !u.EmailVerified {
		t.Fatalf("getUserInfo not used: %+v", u)
	}
	accs := accounts(t, e, "fake")
	if len(accs) != 1 || accs[0].AccountID != "42" || *accs[0].AccessToken != "custom-at" || *accs[0].Scope != "a,b" || accs[0].AccessTokenExpiresAt == nil {
		t.Fatalf("accounts: %+v", accs)
	}
}

// ─── Interop with the social plugin ──────────────────────────────────────────

func TestSocialPluginInterop(t *testing.T) {
	// both plugins installed: the generic providers are also social providers
	e := newEnv(t, envOpts{extra: func(_ *socialtest.Provider, p *genericoauth.Plugin) []compattest.Option {
		return []compattest.Option{compattest.WithPlugin(social.New(socialconfig.SocialConfig{}, social.WithProviders(p.SocialProviders()...)))}
	}})
	// Step 1: /sign-in/social with the generic provider uses the social callback
	r := e.s.Post(t, "/api/auth/sign-in/social", map[string]any{"provider": "fake", "callbackURL": "/s", "disableRedirect": true})
	var body redirectBody
	r.JSON(t, &body)
	u, _ := url.Parse(body.URL)
	if u.Query().Get("redirect_uri") != baseURL+"/api/auth/callback/fake" {
		t.Fatalf("social redirect_uri: %s", body.URL)
	}
	if loc := location(t, e.s.Get(t, e.authorize(t, body.URL))); loc != "/s" {
		t.Fatalf("social flow: %s", loc)
	}
	// Step 2: the generic-oauth flow still works next to it
	if loc := location(t, e.flow(t, map[string]any{"callbackURL": "/g"})); loc != "/g" {
		t.Fatalf("generic flow: %s", loc)
	}
	// Step 3: the social account endpoints work with the generic provider
	at := e.s.Post(t, "/api/auth/get-access-token", map[string]any{"providerId": "fake"})
	if at.Status != http.StatusOK || !strings.Contains(string(at.Body), `"accessToken":"at-`) {
		t.Fatalf("get-access-token: %d %s", at.Status, at.Body)
	}
	rt := e.s.Post(t, "/api/auth/refresh-token", map[string]any{"providerId": "fake"})
	if rt.Status != http.StatusOK || e.fake.RefreshCount() != 1 {
		t.Fatalf("refresh-token: %d %s", rt.Status, rt.Body)
	}
}

// ─── Presets ─────────────────────────────────────────────────────────────────

func TestPresets(t *testing.T) {
	base := gproviders.PresetOptions{ClientID: "id", ClientSecret: "secret", PKCE: true}
	cases := []struct {
		cfg                         goconfig.ProviderConfig
		id, discovery, auth, scopes string
		userInfo                    bool
	}{
		{gproviders.Auth0(gproviders.Auth0Options{PresetOptions: base, Domain: "https://tenant.auth0.com"}), "auth0", "https://tenant.auth0.com/.well-known/openid-configuration", "", "openid profile email", false},
		{gproviders.Keycloak(gproviders.IssuerOptions{PresetOptions: base, Issuer: "https://kc.example.com/realms/r/"}), "keycloak", "https://kc.example.com/realms/r/.well-known/openid-configuration", "", "openid profile email", false},
		{gproviders.Okta(gproviders.IssuerOptions{PresetOptions: base, Issuer: "https://acme.okta.com"}), "okta", "https://acme.okta.com/.well-known/openid-configuration", "", "openid profile email", false},
		{gproviders.MicrosoftEntraID(gproviders.MicrosoftEntraIDOptions{PresetOptions: base, TenantID: "t1"}), "microsoft-entra-id", "", "https://login.microsoftonline.com/t1/oauth2/v2.0/authorize", "openid profile email", true},
		{gproviders.Slack(base), "slack", "", "https://slack.com/openid/connect/authorize", "openid profile email", true},
		{gproviders.Line(gproviders.LineOptions{PresetOptions: base, ProviderID: "line-jp"}), "line-jp", "", "https://access.line.me/oauth2/v2.1/authorize", "openid profile email", true},
		{gproviders.HubSpot(base), "hubspot", "", "https://app.hubspot.com/oauth/authorize", "oauth", true},
		{gproviders.Patreon(base), "patreon", "", "https://www.patreon.com/oauth2/authorize", "identity[email]", true},
		{gproviders.Gumroad(base), "gumroad", "", "https://gumroad.com/oauth/authorize", "view_profile", true},
	}
	for _, c := range cases {
		if c.cfg.ProviderID != c.id || c.cfg.DiscoveryURL != c.discovery || c.cfg.AuthorizationURL != c.auth ||
			strings.Join(c.cfg.Scopes, " ") != c.scopes || (c.cfg.GetUserInfo != nil) != c.userInfo ||
			c.cfg.ClientID != "id" || c.cfg.ClientSecret != "secret" || !c.cfg.PKCE {
			t.Errorf("%s: unexpected config %+v", c.id, c.cfg)
		}
	}
	if gproviders.HubSpot(base).Authentication != socialproviders.AuthPost {
		t.Error("hubspot must use post authentication")
	}
	if got := gproviders.Slack(gproviders.PresetOptions{Scopes: []string{"x"}}).Scopes; strings.Join(got, ",") != "x" {
		t.Errorf("custom scopes ignored: %v", got)
	}
}

func TestPresetUserInfo(t *testing.T) {
	// a stub Graph endpoint: the Entra preset maps given/family name and preferred_username
	rt := roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != gproviders.MicrosoftEntraIDUserInfoURL || r.Header.Get("Authorization") != "Bearer tok" {
			return nil, errors.New("unexpected request " + r.URL.String())
		}
		return jsonResponse(`{"sub":"ms-1","given_name":"Ada","family_name":"Lovelace","preferred_username":"ada@example.com"}`), nil
	})
	cfg := gproviders.MicrosoftEntraID(gproviders.MicrosoftEntraIDOptions{TenantID: "t", PresetOptions: gproviders.PresetOptions{HTTPClient: &http.Client{Transport: rt}}})
	profile, err := cfg.GetUserInfo(context.Background(), socialproviders.OAuth2Tokens{AccessToken: "tok"})
	if err != nil || profile["id"] != "ms-1" || profile["name"] != "Ada Lovelace" || profile["email"] != "ada@example.com" || profile["emailVerified"] != false {
		t.Fatalf("entra profile: %v %v", profile, err)
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func jsonResponse(body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}
