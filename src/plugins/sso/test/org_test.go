package test

import (
	"context"
	"net/http"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
	ssoconfig "github.com/better-go-auth/goauth/src/plugins/sso/config"
)

// createOrg creates an organization as the signed-in user (its owner) and returns its id.
func (e *env) createOrg(t *testing.T, name, slug string) string {
	t.Helper()
	r := e.s.Post(t, "/api/auth/organization/create", map[string]any{"name": name, "slug": slug})
	if r.Status != http.StatusOK {
		t.Fatalf("create org: %d %s", r.Status, r.Body)
	}
	var out struct {
		ID string `json:"id"`
	}
	r.JSON(t, &out)
	return out.ID
}

// memberRole returns the role of userID in orgID ("" when not a member).
func (e *env) memberRole(t *testing.T, orgID, userID string) string {
	t.Helper()
	m, err := e.org.OrganizationStore().FindMember(context.Background(), orgID, userID)
	if err != nil {
		t.Fatal(err)
	}
	if m == nil {
		return ""
	}
	return m.Role
}

func TestOrganizationProvisioningOIDC(t *testing.T) {
	e := newEnv(t, envOpts{withOrg: true, sso: func(_ *socialtest.Provider, c *ssoconfig.SSOConfig) {
		c.OrganizationProvisioning = &ssoconfig.OrganizationProvisioning{GetRole: func(_ context.Context, d ssoconfig.ProvisionUserData) (string, error) {
			if d.UserInfo["email"] == "boss@acme.com" {
				return "admin", nil
			}
			return "member", nil
		}}
	}})
	e.signUp(t, "owner@acme.com")
	orgID := e.createOrg(t, "Acme", "acme")
	ownerJar := e.s.Client.Jar

	// Step 1: an organization provider (the owner is an org owner)
	body := e.oidcProvider("acme-oidc", "acme.com")
	body["organizationId"] = orgID
	out := e.mustRegister(t, body)
	if out["organizationId"] != orgID {
		t.Fatalf("organizationId %v", out)
	}

	// Step 2: sign-in by organization slug; users join with the role from getRole
	e.freshBrowser()
	e.fake.SetUser(socialtest.Profile{Sub: "b-1", Email: "boss@acme.com", Name: "Boss"})
	location(t, e.oidcFlow(t, map[string]any{"organizationSlug": "acme", "callbackURL": "/x"}))
	boss := e.userByEmail(t, "boss@acme.com")
	if role := e.memberRole(t, orgID, boss.ID); role != "admin" {
		t.Fatalf("boss role %q", role)
	}
	e.freshBrowser()
	e.fake.SetUser(socialtest.Profile{Sub: "w-1", Email: "worker@acme.com", Name: "Worker"})
	location(t, e.oidcFlow(t, map[string]any{"email": "worker@acme.com", "callbackURL": "/x"}))
	worker := e.userByEmail(t, "worker@acme.com")
	if role := e.memberRole(t, orgID, worker.ID); role != "member" {
		t.Fatalf("worker role %q", role)
	}

	// Step 3: org admins see the organization provider; plain members do not
	r := e.s.Get(t, "/api/auth/sso/providers")
	var list struct {
		Providers []map[string]any `json:"providers"`
	}
	r.JSON(t, &list)
	if len(list.Providers) != 0 {
		t.Fatalf("member sees %v", list.Providers)
	}
	expectError(t, e.s.Get(t, "/api/auth/sso/get-provider?providerId=acme-oidc"), http.StatusForbidden, "", "You don't have access to this provider")
	e.s.Client.Jar = ownerJar
	e.s.Get(t, "/api/auth/sso/providers").JSON(t, &list)
	if len(list.Providers) != 1 || list.Providers[0]["organizationId"] != orgID {
		t.Fatalf("owner list %v", list.Providers)
	}

	// Step 4: members (not admins) and non-members cannot register providers for the organization
	e.freshBrowser()
	e.signUp(t, "outsider@else.com")
	body = e.oidcProvider("acme-2", "acme.com")
	body["organizationId"] = orgID
	expectError(t, e.register(t, body), http.StatusBadRequest, "", "You are not a member of the organization")
}

func TestOrganizationProvisioningSAMLAndDisabled(t *testing.T) {
	e := newEnv(t, envOpts{withOrg: true, sso: func(_ *socialtest.Provider, c *ssoconfig.SSOConfig) {
		c.OrganizationProvisioning = &ssoconfig.OrganizationProvisioning{DefaultRole: "admin"}
	}})
	e.signUp(t, "admin@saml.example")
	orgID := e.createOrg(t, "SAML Co", "saml-co")
	idp := newTestIdP(t, "https://idp.saml.example/metadata")
	body := samlBody(idp, nil)
	body["organizationId"] = orgID
	e.mustRegister(t, body)
	e.freshBrowser()
	location(t, e.postSAML(t, "/api/auth/sso/saml2/callback/"+samlProvider, idp.response(t, janeOpts()), ""))
	jane := e.userByEmail(t, "jane@saml.example")
	if role := e.memberRole(t, orgID, jane.ID); role != "admin" {
		t.Fatalf("defaultRole %q", role)
	}

	// provisioning disabled: no membership
	e2 := newEnv(t, envOpts{withOrg: true, sso: func(_ *socialtest.Provider, c *ssoconfig.SSOConfig) {
		c.OrganizationProvisioning = &ssoconfig.OrganizationProvisioning{Disabled: true}
	}})
	e2.signUp(t, "admin@saml.example")
	org2 := e2.createOrg(t, "SAML Two", "saml-two")
	body = samlBody(idp, nil)
	body["organizationId"] = org2
	e2.mustRegister(t, body)
	e2.freshBrowser()
	location(t, e2.postSAML(t, "/api/auth/sso/saml2/callback/"+samlProvider, idp.response(t, janeOpts()), ""))
	if role := e2.memberRole(t, org2, e2.userByEmail(t, "jane@saml.example").ID); role != "" {
		t.Fatalf("disabled provisioning added role %q", role)
	}
}

func TestAssignOrganizationByDomainAfterSocialSignIn(t *testing.T) {
	var social *socialtest.Provider
	e := newEnv(t, envOpts{withOrg: true, core: func(c *config.AuthConfig) {
		social = socialtest.New(clientID, clientSecret)
		c.SocialProviders = []providers.Provider{genericFake(social)}
	}})
	t.Cleanup(social.Close)
	social.SetRedirectBase(e.s.URL)
	e.signUp(t, "owner@domainco.com")
	orgID := e.createOrg(t, "Domain Co", "domain-co")
	body := e.oidcProvider("domainco", "domainco.com")
	body["organizationId"] = orgID
	e.mustRegister(t, body)

	// a Google-style social sign-in with an @domainco.com email joins the SSO provider's organization
	e.freshBrowser()
	social.SetUser(socialtest.Profile{Sub: "g-1", Email: "dev@domainco.com", EmailVerified: true, Name: "Dev"})
	r := e.s.Post(t, "/api/auth/sign-in/social", map[string]any{"provider": "fake", "callbackURL": "/x"})
	var out redirectBody
	r.JSON(t, &out)
	if r.Status != http.StatusOK || out.URL == "" {
		t.Fatalf("sign-in/social %d %s", r.Status, r.Body)
	}
	location(t, e.s.Get(t, e.authorize(t, out.URL)))
	dev := e.userByEmail(t, "dev@domainco.com")
	if dev == nil {
		t.Fatal("social user not created")
	}
	if role := e.memberRole(t, orgID, dev.ID); role != "member" {
		t.Fatalf("domain assignment role %q", role)
	}
}
