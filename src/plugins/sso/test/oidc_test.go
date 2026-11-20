package test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
	ssoconfig "github.com/better-go-auth/goauth/src/plugins/sso/config"
)

func TestRegisterOIDCWithDiscovery(t *testing.T) {
	e := newEnv(t, envOpts{})
	userID := e.signUp(t, "admin@corp.com")

	// Step 1: registration hydrates the endpoints from the discovery document
	out := e.mustRegister(t, e.oidcProvider("corp", "corp.com"))
	if out["providerId"] != "corp" || out["domain"] != "corp.com" || out["userId"] != userID || out["issuer"] != e.fake.Issuer {
		t.Fatalf("unexpected provider %v", out)
	}
	if out["redirectURI"] != authBase+"/sso/callback/corp" {
		t.Fatalf("redirectURI = %v", out["redirectURI"])
	}
	if out["samlConfig"] != nil || out["organizationId"] != nil {
		t.Fatalf("samlConfig / organizationId must be null: %v", out)
	}
	if _, ok := out["domainVerified"]; ok {
		t.Fatalf("domainVerified only exists with domain verification: %v", out)
	}
	oc, _ := out["oidcConfig"].(map[string]any)
	want := map[string]any{
		"issuer": e.fake.Issuer, "clientId": clientID, "clientSecret": clientSecret,
		"authorizationEndpoint": e.fake.AuthorizationEndpoint(), "tokenEndpoint": e.fake.TokenEndpoint(),
		"tokenEndpointAuthentication": "client_secret_basic", "jwksEndpoint": e.fake.JWKSEndpoint(),
		"pkce": true, "discoveryEndpoint": e.fake.DiscoveryURL(), "userInfoEndpoint": e.fake.UserInfoEndpoint(),
		"overrideUserInfo": false,
	}
	for k, v := range want {
		if oc[k] != v {
			t.Fatalf("oidcConfig.%s = %v, want %v (%v)", k, oc[k], v, oc)
		}
	}
	// Step 2: the row is stored with the JSON config
	row := e.providerRow(t, "corp")
	if row == nil || jsonOf(t, row["oidcConfig"])["clientSecret"] != clientSecret {
		t.Fatalf("stored row %v", row)
	}
}

func TestOIDCFullFlow(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.signUp(t, "admin@corp.com")
	e.mustRegister(t, e.oidcProvider("corp", "corp.com"))
	e.fake.SetUser(socialtest.Profile{Sub: "idp-42", Email: "Jane@Corp.com", EmailVerified: true, Name: "Jane Doe", Picture: "https://img/jane.png"})

	// Step 1: sign-in by email domain → authorization URL with PKCE, login_hint and the default scopes
	e.freshBrowser()
	authURL := e.startSignIn(t, map[string]any{"email": "jane@corp.com", "callbackURL": "/dashboard", "newUserCallbackURL": "/welcome"})
	u, _ := url.Parse(authURL)
	q := u.Query()
	if !strings.HasPrefix(authURL, e.fake.AuthorizationEndpoint()) || q.Get("client_id") != clientID || q.Get("redirect_uri") != authBase+"/sso/callback/corp" {
		t.Fatalf("authorization URL %s", authURL)
	}
	if q.Get("scope") != "openid email profile offline_access" || q.Get("code_challenge_method") != "S256" || q.Get("login_hint") != "jane@corp.com" {
		t.Fatalf("authorization URL params %v", q)
	}

	// Step 2: the callback creates the user and the account, then goes to newUserCallbackURL
	r := e.s.Get(t, e.authorize(t, authURL))
	if loc := location(t, r); loc != "/welcome" {
		t.Fatalf("redirect = %s", loc)
	}
	if sessionCookie(r) == nil {
		t.Fatal("no session cookie")
	}
	user := e.userByEmail(t, "jane@corp.com")
	if user == nil || user.Name != "Jane Doe" || user.EmailVerified {
		t.Fatalf("user %+v (email_verified is not trusted by default)", user)
	}
	accs := e.accountsOf(t, user.ID)
	if len(accs) != 1 || string(accs[0].ProviderID) != "corp" || accs[0].AccountID != "idp-42" || accs[0].AccessToken == nil {
		t.Fatalf("accounts %+v", accs)
	}

	// Step 3: a returning user goes to callbackURL
	e.freshBrowser()
	r = e.oidcFlow(t, map[string]any{"providerId": "corp", "callbackURL": "/dashboard", "newUserCallbackURL": "/welcome"})
	if loc := location(t, r); loc != "/dashboard" {
		t.Fatalf("returning redirect = %s", loc)
	}
	s := e.s.Get(t, "/api/auth/get-session")
	if s.Status != http.StatusOK || !strings.Contains(string(s.Body), "jane@corp.com") {
		t.Fatalf("get-session: %d %s", s.Status, s.Body)
	}
}

func TestOIDCIDTokenPathAndTrustEmailVerified(t *testing.T) {
	e := newEnv(t, envOpts{sso: func(_ *socialtest.Provider, c *ssoconfig.SSOConfig) { c.TrustEmailVerified = true }})
	e.signUp(t, "admin@corp.com")
	// skipDiscovery without a userinfo endpoint: the user comes from the verified id_token
	e.mustRegister(t, map[string]any{
		"providerId": "idt", "issuer": e.fake.Issuer, "domain": "idt.com",
		"oidcConfig": map[string]any{
			"clientId": clientID, "clientSecret": clientSecret, "skipDiscovery": true,
			"authorizationEndpoint": e.fake.AuthorizationEndpoint(), "tokenEndpoint": e.fake.TokenEndpoint(),
			"jwksEndpoint": e.fake.JWKSEndpoint(),
		},
	})
	e.fake.SetUser(socialtest.Profile{Sub: "idt-1", Email: "bob@idt.com", EmailVerified: true, Name: "Bob"})
	e.freshBrowser()
	r := e.oidcFlow(t, map[string]any{"providerId": "idt", "callbackURL": "/home"})
	if loc := location(t, r); loc != "/home" {
		t.Fatalf("redirect %s", loc)
	}
	u := e.userByEmail(t, "bob@idt.com")
	if u == nil || !u.EmailVerified {
		t.Fatalf("trustEmailVerified must copy email_verified: %+v", u)
	}
}
