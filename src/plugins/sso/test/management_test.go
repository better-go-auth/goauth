package test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
	ssoconfig "github.com/better-go-auth/goauth/src/plugins/sso/config"
)

func TestProviderManagement(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.signUp(t, "owner@corp.com")
	idp := newTestIdP(t, "https://idp.manage.example")
	e.mustRegister(t, e.oidcProvider("oidc-1", "corp.com"))
	e.mustRegister(t, samlBody(idp, nil))
	ownerJar := e.s.Client.Jar

	// Step 1: list: sanitized, secrets removed
	r := e.s.Get(t, "/api/auth/sso/providers")
	if r.Status != http.StatusOK || strings.Contains(string(r.Body), clientSecret) || strings.Contains(string(r.Body), "BEGIN CERTIFICATE") {
		t.Fatalf("list %d %s", r.Status, r.Body)
	}
	var list struct {
		Providers []map[string]any `json:"providers"`
	}
	r.JSON(t, &list)
	if len(list.Providers) != 2 {
		t.Fatalf("providers %v", list.Providers)
	}
	for _, p := range list.Providers {
		switch p["providerId"] {
		case "oidc-1":
			oc := p["oidcConfig"].(map[string]any)
			if p["type"] != "oidc" || oc["clientIdLastFour"] != "****ient" || p["domainVerified"] != false || p["organizationId"] != nil {
				t.Fatalf("oidc sanitized %v", p)
			}
			if p["spMetadataUrl"] != authBase+"/sso/saml2/sp/metadata?providerId=oidc-1" {
				t.Fatalf("spMetadataUrl %v", p["spMetadataUrl"])
			}
		case samlProvider:
			cert := p["samlConfig"].(map[string]any)["certificate"].(map[string]any)
			if p["type"] != "saml" || cert["publicKeyAlgorithm"] != "RSA" || len(cert["fingerprintSha256"].(string)) != 95 || !strings.HasSuffix(cert["notAfter"].(string), " GMT") {
				t.Fatalf("saml sanitized %v", p)
			}
		default:
			t.Fatalf("unexpected %v", p)
		}
	}

	// Step 2: get, update (domain change, OIDC merge), errors
	r = e.s.Get(t, "/api/auth/sso/get-provider?providerId=oidc-1")
	if r.Status != http.StatusOK {
		t.Fatalf("get %d %s", r.Status, r.Body)
	}
	expectError(t, e.s.Get(t, "/api/auth/sso/get-provider?providerId=nope"), http.StatusNotFound, "", "Provider not found")
	expectError(t, e.s.Post(t, "/api/auth/sso/update-provider", map[string]any{"providerId": "oidc-1"}), http.StatusBadRequest, "", "No fields provided for update")
	r = e.s.Post(t, "/api/auth/sso/update-provider", map[string]any{"providerId": "oidc-1", "domain": "new.com", "oidcConfig": map[string]any{"scopes": []string{"openid"}, "clientId": "rotated-id-9999"}})
	if r.Status != http.StatusOK {
		t.Fatalf("update %d %s", r.Status, r.Body)
	}
	var upd map[string]any
	r.JSON(t, &upd)
	if upd["domain"] != "new.com" || upd["oidcConfig"].(map[string]any)["clientIdLastFour"] != "****9999" {
		t.Fatalf("updated %v", upd)
	}
	stored := jsonOf(t, e.providerRow(t, "oidc-1")["oidcConfig"])
	if stored["clientSecret"] != clientSecret || stored["pkce"] != true || stored["tokenEndpoint"] != e.fake.TokenEndpoint() {
		t.Fatalf("merge lost fields: %v", stored)
	}
	expectError(t, e.s.Post(t, "/api/auth/sso/update-provider", map[string]any{"providerId": "oidc-1", "samlConfig": map[string]any{"audience": "x"}}), http.StatusBadRequest, "", "Cannot update SAML config for a provider that doesn't have SAML configured")
	r = e.s.Post(t, "/api/auth/sso/update-provider", map[string]any{"providerId": samlProvider, "samlConfig": map[string]any{"audience": "aud-2"}})
	if r.Status != http.StatusOK || jsonOf(t, e.providerRow(t, samlProvider)["samlConfig"])["cert"] != idp.certPEM {
		t.Fatalf("saml update %d %s", r.Status, r.Body)
	}

	// Step 3: another user cannot see or change the providers
	e.freshBrowser()
	e.signUp(t, "intruder@other.com")
	r = e.s.Get(t, "/api/auth/sso/providers")
	r.JSON(t, &list)
	if len(list.Providers) != 0 {
		t.Fatalf("intruder sees %v", list.Providers)
	}
	expectError(t, e.s.Get(t, "/api/auth/sso/get-provider?providerId=oidc-1"), http.StatusForbidden, "", "You don't have access to this provider")
	expectError(t, e.s.Post(t, "/api/auth/sso/delete-provider", map[string]any{"providerId": "oidc-1"}), http.StatusForbidden, "", "You don't have access to this provider")

	// Step 4: the owner deletes
	e.s.Client.Jar = ownerJar
	r = e.s.Post(t, "/api/auth/sso/delete-provider", map[string]any{"providerId": "oidc-1"})
	if r.Status != http.StatusOK || strings.TrimSpace(string(r.Body)) != `{"success":true}` {
		t.Fatalf("delete %d %s", r.Status, r.Body)
	}
	if e.providerRow(t, "oidc-1") != nil {
		t.Fatal("provider still stored")
	}
	// anonymous requests are refused
	e.freshBrowser()
	expectError(t, e.s.Get(t, "/api/auth/sso/providers"), http.StatusUnauthorized, "UNAUTHORIZED", "")
}

// fakeDNS is a TXT resolver for domain verification tests.
type fakeDNS struct {
	mu      sync.Mutex
	records map[string][]string
}

func (d *fakeDNS) lookup(_ context.Context, name string) ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if r, ok := d.records[name]; ok {
		return r, nil
	}
	return nil, errors.New("no such host")
}

func (d *fakeDNS) set(name string, vals ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.records[name] = vals
}

func TestDomainVerification(t *testing.T) {
	dns := &fakeDNS{records: map[string][]string{}}
	e := newEnv(t, envOpts{
		sso: func(_ *socialtest.Provider, c *ssoconfig.SSOConfig) {
			c.DomainVerification = ssoconfig.DomainVerification{Enabled: true, LookupTXT: dns.lookup}
		},
	})
	e.signUp(t, "owner@verified.com")

	// Step 1: registration returns domainVerified=false and a token
	out := e.mustRegister(t, e.oidcProvider("dv", "verified.com"))
	token, _ := out["domainVerificationToken"].(string)
	if out["domainVerified"] != false || len(token) != 24 {
		t.Fatalf("register %v", out)
	}
	ownerJar := e.s.Client.Jar

	// Step 2: sign-in is refused until the domain is verified
	expectError(t, e.s.Post(t, "/api/auth/sign-in/sso", map[string]any{"providerId": "dv", "callbackURL": "/x"}), http.StatusUnauthorized, "", "Provider domain has not been verified")

	// Step 3: request returns the pending token (201); verify fails without the TXT record (502)
	r := e.s.Post(t, "/api/auth/sso/request-domain-verification", map[string]any{"providerId": "dv"})
	if r.Status != http.StatusCreated || !strings.Contains(string(r.Body), token) {
		t.Fatalf("request %d %s", r.Status, r.Body)
	}
	expectError(t, e.s.Post(t, "/api/auth/sso/verify-domain", map[string]any{"providerId": "dv"}), http.StatusBadGateway, "DOMAIN_VERIFICATION_FAILED", "Unable to verify domain ownership. Try again later")
	expectError(t, e.s.Post(t, "/api/auth/sso/verify-domain", map[string]any{"providerId": "nope"}), http.StatusNotFound, "PROVIDER_NOT_FOUND", "Provider not found")

	// Step 4: another user may not verify
	e.freshBrowser()
	e.signUp(t, "other@x.com")
	expectError(t, e.s.Post(t, "/api/auth/sso/verify-domain", map[string]any{"providerId": "dv"}), http.StatusForbidden, "INSUFICCIENT_ACCESS", "")
	e.s.Client.Jar = ownerJar

	// Step 5: the TXT record verifies the domain (204); then it is already verified (409)
	dns.set("_better-auth-token-dv.verified.com", "_better-auth-token-dv="+token)
	r = e.s.Post(t, "/api/auth/sso/verify-domain", map[string]any{"providerId": "dv"})
	if r.Status != http.StatusNoContent {
		t.Fatalf("verify %d %s", r.Status, r.Body)
	}
	expectError(t, e.s.Post(t, "/api/auth/sso/verify-domain", map[string]any{"providerId": "dv"}), http.StatusConflict, "DOMAIN_VERIFIED", "Domain has already been verified")

	// Step 6: a verified domain makes the provider trusted for account linking: the existing local user
	// (unverified IdP email) is linked because the email matches the verified domain
	if err := markVerified(e, "owner@verified.com"); err != nil {
		t.Fatal(err)
	}
	e.freshBrowser()
	e.fake.SetUser(socialtest.Profile{Sub: "dv-1", Email: "owner@verified.com", EmailVerified: false, Name: "Owner"})
	r = e.oidcFlow(t, map[string]any{"providerId": "dv", "callbackURL": "/ok"})
	if loc := location(t, r); loc != "/ok" {
		t.Fatalf("trusted linking: %s", loc)
	}
	u := e.userByEmail(t, "owner@verified.com")
	if accs := e.accountsOf(t, u.ID); len(accs) != 2 {
		t.Fatalf("expected credential + sso accounts, got %+v", accs)
	}

	// Step 7: changing the domain resets the verification
	e.s.Client.Jar = ownerJar
	r = e.s.Post(t, "/api/auth/sso/update-provider", map[string]any{"providerId": "dv", "domain": "changed.com"})
	var upd map[string]any
	r.JSON(t, &upd)
	if upd["domainVerified"] != false {
		t.Fatalf("domain change must reset verification: %v", upd)
	}
}

// markVerified sets emailVerified on a user (account linking requires a verified local email).
func markVerified(e *env, email string) error {
	u, err := e.s.Auth.Repositories().FindUserByEmail(context.Background(), email)
	if err != nil {
		return err
	}
	_, err = e.s.Auth.Repositories().UpdateUser(context.Background(), u.ID, map[string]interface{}{"EmailVerified": true})
	return err
}
