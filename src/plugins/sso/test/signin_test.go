package test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
	ssoconfig "github.com/better-go-auth/goauth/src/plugins/sso/config"
)

func TestSignInProviderLookup(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.signUp(t, "owner@corp.com")
	e.mustRegister(t, e.oidcProvider("multi", "corp.com, subsidiary.org"))
	e.freshBrowser()

	// Step 1: nothing to look the provider up by
	expectError(t, e.s.Post(t, "/api/auth/sign-in/sso", map[string]any{"callbackURL": "/x"}), http.StatusBadRequest, "", "email, organizationSlug, domain or providerId is required")
	// Step 2: domain lists and subdomains match; unknown domains do not
	for _, body := range []map[string]any{
		{"email": "a@subsidiary.org", "callbackURL": "/x"},
		{"email": "a@eu.corp.com", "callbackURL": "/x"},
		{"domain": "corp.com", "callbackURL": "/x"},
		{"providerId": "multi", "callbackURL": "/x"},
	} {
		if u := e.startSignIn(t, body); !strings.HasPrefix(u, e.fake.AuthorizationEndpoint()) {
			t.Fatalf("%v → %s", body, u)
		}
	}
	expectError(t, e.s.Post(t, "/api/auth/sign-in/sso", map[string]any{"email": "a@other.com", "callbackURL": "/x"}), http.StatusNotFound, "", "No provider found for the issuer")
	expectError(t, e.s.Post(t, "/api/auth/sign-in/sso", map[string]any{"providerId": "multi", "providerType": "saml", "callbackURL": "/x"}), http.StatusBadRequest, "", "SAML provider is not configured")
	// Step 3: an untrusted callbackURL is refused before anything else
	expectError(t, e.s.Post(t, "/api/auth/sign-in/sso", map[string]any{"providerId": "multi", "callbackURL": "https://evil.example/cb"}), http.StatusForbidden, "INVALID_CALLBACK_URL", "")
	// Step 4: an explicit loginHint wins over the email
	u := e.startSignIn(t, map[string]any{"email": "a@corp.com", "loginHint": "hint-user", "callbackURL": "/x"})
	if !strings.Contains(u, "login_hint=hint-user") {
		t.Fatalf("login hint: %s", u)
	}
}

func TestDefaultSSO(t *testing.T) {
	e := newEnv(t, envOpts{sso: func(fake *socialtest.Provider, c *ssoconfig.SSOConfig) {
		pkce := true
		c.DefaultSSO = []ssoconfig.DefaultProvider{{Domain: "default.com", ProviderID: "default-oidc", OIDCConfig: &ssoconfig.OIDCConfig{
			Issuer: fake.Issuer, ClientID: clientID, ClientSecret: clientSecret, PKCE: &pkce,
			AuthorizationEndpoint: fake.AuthorizationEndpoint(), TokenEndpoint: fake.TokenEndpoint(),
			JWKSEndpoint: fake.JWKSEndpoint(), UserInfoEndpoint: fake.UserInfoEndpoint(),
		}}}
	}})
	e.fake.SetUser(socialtest.Profile{Sub: "d-1", Email: "user@default.com", Name: "Default User"})
	r := e.oidcFlow(t, map[string]any{"email": "user@default.com", "callbackURL": "/in"})
	if location(t, r) != "/in" || e.userByEmail(t, "user@default.com") == nil {
		t.Fatalf("defaultSSO sign-in failed: %v", r.Header)
	}
}

func TestOIDCCallbackErrors(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.signUp(t, "owner@corp.com")
	e.mustRegister(t, e.oidcProvider("corp", "corp.com"))
	e.freshBrowser()

	// Step 1: the IdP denied access: redirect to the error URL with its error (the state is consumed first)
	e.fake.SetAuthorizeError("access_denied")
	r := e.oidcFlow(t, map[string]any{"providerId": "corp", "callbackURL": "/x", "errorCallbackURL": "/oops"})
	q := errorParams(t, r, "/oops")
	if q.Get("error") != "access_denied" || q.Get("error_description") != "The user denied access" {
		t.Fatalf("idp error: %v", q)
	}
	e.fake.SetAuthorizeError("")

	// Step 2: an unknown state → state_mismatch on the default error page; a missing state is a validation error
	r = e.s.Get(t, "/api/auth/sso/callback/corp?code=x&state=unknown")
	if q := errorParams(t, r, defaultErrorURL); q.Get("error") != "state_mismatch" {
		t.Fatalf("state: %v", q)
	}
	expectError(t, e.s.Get(t, "/api/auth/sso/callback/corp?code=x"), http.StatusBadRequest, "VALIDATION_ERROR", "")

	// Step 3: no code and no error (JavaScript prints undefined)
	authURL := e.startSignIn(t, map[string]any{"providerId": "corp", "callbackURL": "/x"})
	cb := e.authorize(t, authURL)
	cb = strings.Replace(cb, "code=", "unused=", 1)
	r = e.s.Get(t, cb)
	if loc := location(t, r); loc != defaultErrorURL+"?error=undefined&error_description=undefined" {
		t.Fatalf("no code: %s", loc)
	}

	// Step 4: the provider was deleted between sign-in and callback
	authURL = e.startSignIn(t, map[string]any{"providerId": "corp", "callbackURL": "/x"})
	cb = e.authorize(t, authURL)
	cb = strings.Replace(cb, "/sso/callback/corp", "/sso/callback/gone", 1)
	r = e.s.Get(t, cb)
	if loc := location(t, r); loc != defaultErrorURL+"?error=invalid_provider&error_description=provider not found" {
		t.Fatalf("unknown provider: %s", loc)
	}

	// Step 5: the userinfo endpoint fails
	e.fake.SetUserInfoFailure(true)
	r = e.oidcFlow(t, map[string]any{"providerId": "corp", "callbackURL": "/x"})
	if q := errorParams(t, r, defaultErrorURL); q.Get("error") != "invalid_provider" || q.Get("error_description") != "Internal Server Error" {
		t.Fatalf("userinfo failure: %v", q)
	}
	e.fake.SetUserInfoFailure(false)

	// Step 6: the profile has no email
	e.fake.SetUser(socialtest.Profile{Sub: "no-mail"})
	r = e.oidcFlow(t, map[string]any{"providerId": "corp", "callbackURL": "/x"})
	if loc := location(t, r); loc != defaultErrorURL+"?error=invalid_provider&error_description=missing_user_info" {
		t.Fatalf("missing email: %s", loc)
	}
}

func TestOIDCAccountLinkingAndSignUpPolicy(t *testing.T) {
	e := newEnv(t, envOpts{sso: func(_ *socialtest.Provider, c *ssoconfig.SSOConfig) { c.DisableImplicitSignUp = true }})
	e.signUp(t, "owner@corp.com")
	e.mustRegister(t, e.oidcProvider("corp", "corp.com"))
	e.freshBrowser()

	// Step 1: disableImplicitSignUp: a new user is refused…
	e.fake.SetUser(socialtest.Profile{Sub: "n-1", Email: "new@corp.com", Name: "New"})
	r := e.oidcFlow(t, map[string]any{"providerId": "corp", "callbackURL": "/x"})
	if q := errorParams(t, r, defaultErrorURL); q.Get("error") != "signup disabled" {
		t.Fatalf("signup disabled: %v (%s)", q, location(t, r))
	}
	// …unless the sign-in asks for it
	r = e.oidcFlow(t, map[string]any{"providerId": "corp", "callbackURL": "/x", "requestSignUp": true})
	if location(t, r) != "/x" || e.userByEmail(t, "new@corp.com") == nil {
		t.Fatal("requestSignUp must create the user")
	}

	// Step 2: an existing local user is not linked when the IdP email is not trusted
	e.freshBrowser()
	e.fake.SetUser(socialtest.Profile{Sub: "o-1", Email: "owner@corp.com", EmailVerified: true, Name: "Owner"})
	r = e.oidcFlow(t, map[string]any{"providerId": "corp", "callbackURL": "/x"})
	if loc := location(t, r); loc != defaultErrorURL+"?error=account+not+linked" {
		t.Fatalf("account not linked: %s", loc)
	}
}

func TestOIDCProvisionUserAndOverride(t *testing.T) {
	var calls []string
	e := newEnv(t, envOpts{sso: func(_ *socialtest.Provider, c *ssoconfig.SSOConfig) {
		c.ProvisionUserOnEveryLogin = true
		c.DefaultOverrideUserInfo = true
		c.ProvisionUser = func(_ context.Context, d ssoconfig.ProvisionUserData) error {
			if d.Token == nil || d.Token.AccessToken == "" || d.Provider.ProviderID != "corp" {
				t.Errorf("provisionUser data %+v", d)
			}
			calls = append(calls, d.User.Email)
			return nil
		}
	}})
	e.signUp(t, "owner@corp.com")
	e.mustRegister(t, e.oidcProvider("corp", "corp.com"))
	e.freshBrowser()
	e.fake.SetUser(socialtest.Profile{Sub: "p-1", Email: "p@corp.com", Name: "First Name"})
	location(t, e.oidcFlow(t, map[string]any{"providerId": "corp", "callbackURL": "/x"}))
	// overrideUserInfo: the next sign-in rewrites the profile
	e.freshBrowser()
	e.fake.SetUser(socialtest.Profile{Sub: "p-1", Email: "p@corp.com", Name: "Renamed"})
	location(t, e.oidcFlow(t, map[string]any{"providerId": "corp", "callbackURL": "/x"}))
	if u := e.userByEmail(t, "p@corp.com"); u == nil || u.Name != "Renamed" {
		t.Fatalf("overrideUserInfo: %+v", u)
	}
	if len(calls) != 2 {
		t.Fatalf("provisionUserOnEveryLogin calls %v", calls)
	}
}
