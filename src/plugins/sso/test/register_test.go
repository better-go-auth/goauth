package test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
	ssoconfig "github.com/better-go-auth/goauth/src/plugins/sso/config"
)

// genericFake is a social provider "fake" on the fake IdP (its id becomes reserved for SSO providers).
func genericFake(fake *socialtest.Provider) providers.Provider {
	return providers.Generic(providers.GenericOptions{
		ProviderID: "fake",
		Issuer:     fake.Issuer,
		ProviderOptions: providers.ProviderOptions{
			ClientID: clientID, ClientSecret: clientSecret,
			AuthorizationEndpoint: fake.AuthorizationEndpoint(), TokenEndpoint: fake.TokenEndpoint(),
			UserInfoEndpoint: fake.UserInfoEndpoint(), JWKSEndpoint: fake.JWKSEndpoint(),
		},
	})
}

func TestRegisterValidation(t *testing.T) {
	e := newEnv(t, envOpts{
		sso: func(_ *socialtest.Provider, c *ssoconfig.SSOConfig) { c.ProvidersLimit = 2 },
		core: func(c *config.AuthConfig) {
			c.Account.AccountLinking.TrustedProviders = []string{"trusted-one"}
		},
	})

	// Step 1: a session is required
	expectError(t, e.register(t, e.oidcProvider("p1", "a.com")), http.StatusUnauthorized, "UNAUTHORIZED", "")
	e.signUp(t, "owner@a.com")

	// Step 2: issuer, reserved ids, SAML entry point
	body := e.oidcProvider("p1", "a.com")
	body["issuer"] = "not a url"
	expectError(t, e.register(t, body), http.StatusBadRequest, "", "Invalid issuer. Must be a valid URL")
	for _, id := range []string{"credential", "trusted-one"} {
		expectError(t, e.register(t, e.oidcProvider(id, "a.com")), http.StatusUnprocessableEntity, "", "This providerId is reserved and cannot be used for an SSO provider")
	}
	expectError(t, e.register(t, map[string]any{"providerId": "s1", "issuer": "https://idp.example", "domain": "a.com",
		"samlConfig": map[string]any{"entryPoint": "not-a-url", "cert": "x", "callbackUrl": "x", "spMetadata": map[string]any{}}}),
		http.StatusBadRequest, "", "SAML configuration requires either idpMetadata.metadata (IdP metadata XML), idpMetadata.singleSignOnService, or a valid entryPoint URL")
	r := e.register(t, map[string]any{"providerId": "s2", "issuer": "https://idp.example", "domain": "a.com",
		"samlConfig": map[string]any{"entryPoint": "https://idp.example/sso", "cert": "x", "callbackUrl": "x", "spMetadata": map[string]any{}, "signatureAlgorithm": "md5"}})
	expectError(t, r, http.StatusBadRequest, "SAML_UNKNOWN_ALGORITHM", "SAML signature algorithm not recognized: md5")

	// Step 3: discovery errors
	untrusted := e.oidcProvider("p1", "a.com")
	untrusted["issuer"] = "https://idp.untrusted.example"
	expectError(t, e.register(t, untrusted), http.StatusBadRequest, "discovery_untrusted_origin", "")
	notFound := e.oidcProvider("p1", "a.com")
	notFound["issuer"] = e.fake.Issuer + "/tenant"
	expectError(t, e.register(t, notFound), http.StatusBadRequest, "discovery_not_found", "")
	mismatch := e.oidcProvider("p1", "a.com")
	mismatch["issuer"] = e.fake.Issuer + "/tenant"
	mismatch["oidcConfig"].(map[string]any)["discoveryEndpoint"] = e.fake.DiscoveryURL()
	r = e.register(t, mismatch)
	expectError(t, r, http.StatusBadRequest, "issuer_mismatch", "")
	private := map[string]any{"providerId": "p1", "issuer": "https://idp.example", "domain": "a.com", "oidcConfig": map[string]any{
		"clientId": "c", "clientSecret": "s", "skipDiscovery": true, "authorizationEndpoint": "https://idp.example/auth",
		"tokenEndpoint": "http://10.1.2.3/token", "jwksEndpoint": "https://idp.example/jwks"}}
	r = e.register(t, private)
	expectError(t, r, http.StatusBadRequest, "discovery_private_host", "")
	if !strings.Contains(string(r.Body), "10.1.2.3") {
		t.Fatalf("private host message %s", r.Body)
	}

	// Step 4: duplicates and the providers limit
	e.mustRegister(t, e.oidcProvider("p1", "a.com"))
	expectError(t, e.register(t, e.oidcProvider("p1", "b.com")), http.StatusUnprocessableEntity, "", "SSO provider with this providerId already exists")
	e.mustRegister(t, e.oidcProvider("p2", "b.com"))
	expectError(t, e.register(t, e.oidcProvider("p3", "c.com")), http.StatusForbidden, "", "You have reached the maximum number of SSO providers")
}

func TestRegisterLimitsAndReservedSocialID(t *testing.T) {
	// Step 1: limit 0 disables registration; social provider ids are reserved
	e := newEnv(t, envOpts{
		sso: func(_ *socialtest.Provider, c *ssoconfig.SSOConfig) { c.ProvidersLimit, c.ProvidersLimitSet = 0, true },
	})
	e.signUp(t, "owner@a.com")
	expectError(t, e.register(t, e.oidcProvider("p1", "a.com")), http.StatusForbidden, "", "SSO provider registration is disabled")

	// Step 2: a limit function per user
	var seen string
	social := socialtest.New("x", "y")
	t.Cleanup(social.Close)
	e2 := newEnv(t, envOpts{
		sso: func(_ *socialtest.Provider, c *ssoconfig.SSOConfig) {
			c.ProvidersLimitFunc = func(_ context.Context, u *models.User) (int, error) { seen = u.Email; return 1, nil }
		},
		core: func(c *config.AuthConfig) { c.SocialProviders = []providers.Provider{genericFake(social)} },
	})
	e2.signUp(t, "func@a.com")
	expectError(t, e2.register(t, e2.oidcProvider("fake", "a.com")), http.StatusUnprocessableEntity, "", "This providerId is reserved and cannot be used for an SSO provider")
	e2.mustRegister(t, e2.oidcProvider("ok", "a.com"))
	expectError(t, e2.register(t, e2.oidcProvider("ok2", "a.com")), http.StatusForbidden, "", "You have reached the maximum number of SSO providers")
	if seen != "func@a.com" {
		t.Fatalf("providersLimit function got %q", seen)
	}
}

func TestRegisterSkipDiscoveryAndSharedRedirectURI(t *testing.T) {
	e := newEnv(t, envOpts{sso: func(_ *socialtest.Provider, c *ssoconfig.SSOConfig) { c.RedirectURI = "/sso/callback" }})
	e.signUp(t, "owner@corp.com")
	out := e.mustRegister(t, map[string]any{
		"providerId": "manual", "issuer": e.fake.Issuer, "domain": "corp.com", "overrideUserInfo": true,
		"oidcConfig": map[string]any{
			"clientId": clientID, "clientSecret": clientSecret, "skipDiscovery": true, "pkce": false,
			"authorizationEndpoint": e.fake.AuthorizationEndpoint(), "tokenEndpoint": e.fake.TokenEndpoint(),
			"userInfoEndpoint": e.fake.UserInfoEndpoint(), "jwksEndpoint": e.fake.JWKSEndpoint(),
			"tokenEndpointAuthentication": "client_secret_post", "scopes": []string{"openid", "email"},
			"mapping": map[string]any{"id": "sub", "email": "email", "name": "name", "extraFields": map[string]any{"pic": "picture"}},
		},
	})
	oc := out["oidcConfig"].(map[string]any)
	if oc["discoveryEndpoint"] != e.fake.Issuer+"/.well-known/openid-configuration" || oc["pkce"] != false || oc["overrideUserInfo"] != true || oc["tokenEndpointAuthentication"] != "client_secret_post" {
		t.Fatalf("oidcConfig %v", oc)
	}
	if out["redirectURI"] != authBase+"/sso/callback" {
		t.Fatalf("shared redirectURI %v", out["redirectURI"])
	}
	// the shared callback finds the provider in the state; no PKCE; client_secret_post
	e.freshBrowser()
	authURL := e.startSignIn(t, map[string]any{"providerId": "manual", "callbackURL": "/app", "scopes": []string{"openid"}})
	if strings.Contains(authURL, "code_challenge") || !strings.Contains(authURL, "scope=openid&") {
		t.Fatalf("authorization URL %s", authURL)
	}
	r := e.s.Get(t, e.authorize(t, authURL))
	if loc := location(t, r); loc != "/app" {
		t.Fatalf("redirect %s", loc)
	}
	if got := e.fake.LastTokenRequest().Get("client_secret"); got != clientSecret {
		t.Fatalf("client_secret_post not used: %v", e.fake.LastTokenRequest())
	}
}
