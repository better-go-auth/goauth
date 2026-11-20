package test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/plugins/scim/config"
)

// memberRole returns userID's role in orgID ("" when not a member).
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

func TestSCIMOrganizationScoping(t *testing.T) {
	e := newEnv(t, envOpts{withOrg: true})
	e.signUp(t, "owner-a@a.com")
	orgA := e.createOrg(t, "org-a")
	tokenA := e.mustToken(t, "okta", orgA)
	if parts := decodeToken(t, tokenA); len(parts) != 3 || parts[2] != orgA {
		t.Fatalf("org token parts %v", parts)
	}
	jarA := e.s.Client.Jar
	e.freshBrowser()
	e.signUp(t, "owner-b@b.com")
	orgB := e.createOrg(t, "org-b")
	// providerId is unique across organizations, so org B uses its own id
	tokenB := e.mustToken(t, "entra", orgB)

	// Step 1: provisioning through org A adds the user to org A as "member"
	r := e.scimDo(t, http.MethodPost, "/scim/v2/Users", tokenA, userBody("alice@a.com", nil))
	if r.Status != http.StatusCreated {
		t.Fatalf("create %d %s", r.Status, r.Body)
	}
	alice := resource(t, r)["id"].(string)
	if role := e.memberRole(t, orgA, alice); role != "member" {
		t.Fatalf("alice role %q", role)
	}

	// Step 2: org B's token cannot see, change or delete org A's user
	scimErr(t, e.scimDo(t, http.MethodGet, "/scim/v2/Users/"+alice, tokenB, nil), http.StatusNotFound, "User not found", "")
	scimErr(t, e.scimDo(t, http.MethodPut, "/scim/v2/Users/"+alice, tokenB, userBody("hacked@b.com", nil)), http.StatusNotFound, "User not found", "")
	scimErr(t, e.scimDo(t, http.MethodDelete, "/scim/v2/Users/"+alice, tokenB, nil), http.StatusNotFound, "User not found", "")
	r = e.scimDo(t, http.MethodGet, "/scim/v2/Users", tokenB, nil)
	if !strings.Contains(string(r.Body), `"totalResults":0`) {
		t.Fatalf("org B list %s", r.Body)
	}
	// a token claiming org A for provider "entra" is invalid
	scimErr(t, e.scimDo(t, http.MethodGet, "/scim/v2/Users", encode(decodeToken(t, tokenB)[0]+":entra:"+orgA), nil), http.StatusUnauthorized, "Invalid SCIM token", "")

	// Step 3: a user removed from org A disappears from org A's SCIM view
	if err := e.org.OrganizationStore().RemoveMember(context.Background(), orgA, alice); err != nil {
		t.Fatal(err)
	}
	scimErr(t, e.scimDo(t, http.MethodGet, "/scim/v2/Users/"+alice, tokenA, nil), http.StatusNotFound, "User not found", "")
	if _, err := e.org.OrganizationStore().AddMember(context.Background(), orgA, alice, "member"); err != nil {
		t.Fatal(err)
	}

	// Step 4: DELETE with an org token deprovisions: membership and SCIM account gone, the user stays
	r = e.scimDo(t, http.MethodDelete, "/scim/v2/Users/"+alice, tokenA, nil)
	if r.Status != http.StatusNoContent {
		t.Fatalf("delete %d %s", r.Status, r.Body)
	}
	if e.memberRole(t, orgA, alice) != "" || e.userByEmail("alice@a.com") == nil {
		t.Fatal("org delete must remove the membership but keep the user")
	}
	scimErr(t, e.scimDo(t, http.MethodGet, "/scim/v2/Users/"+alice, tokenA, nil), http.StatusNotFound, "User not found", "")

	// Step 5: connections are listed per organization role
	r = e.s.Get(t, "/api/auth/scim/list-provider-connections")
	if !strings.Contains(string(r.Body), `"providerId":"entra"`) || strings.Contains(string(r.Body), `"providerId":"okta"`) {
		t.Fatalf("org B owner list %s", r.Body)
	}
	apiErr(t, e.s.Get(t, "/api/auth/scim/get-provider-connection?providerId=okta"), http.StatusForbidden, "", "You must be a member of the organization to access this provider")
	e.s.Client.Jar = jarA
	r = e.s.Get(t, "/api/auth/scim/list-provider-connections")
	if !strings.Contains(string(r.Body), `"providerId":"okta","organizationId":"`+orgA+`"`) {
		t.Fatalf("org A owner list %s", r.Body)
	}
}

func TestSCIMOrganizationRoles(t *testing.T) {
	e := newEnv(t, envOpts{withOrg: true, scim: func(c *config.SCIMConfig) { c.RequiredRole = []string{"owner"} }})
	e.signUp(t, "owner@a.com")
	orgID := e.createOrg(t, "roles")
	e.mustToken(t, "okta", orgID)

	// a plain member may not generate tokens or manage the connection
	e.freshBrowser()
	memberID := e.signUp(t, "member@a.com")
	if _, err := e.org.OrganizationStore().AddMember(context.Background(), orgID, memberID, "member"); err != nil {
		t.Fatal(err)
	}
	apiErr(t, e.generate(t, map[string]any{"providerId": "other", "organizationId": orgID}), http.StatusForbidden, "", "Insufficient role for this operation")
	apiErr(t, e.s.Post(t, "/api/auth/scim/delete-provider-connection", map[string]any{"providerId": "okta"}), http.StatusForbidden, "", "Insufficient role for this operation")
	// non-members are refused
	e.freshBrowser()
	e.signUp(t, "stranger@x.com")
	apiErr(t, e.generate(t, map[string]any{"providerId": "other", "organizationId": orgID}), http.StatusForbidden, "", "You are not a member of the organization")
}

func TestSCIMLinkRequiresOrgMembership(t *testing.T) {
	e := newEnv(t, envOpts{withOrg: true, scim: func(c *config.SCIMConfig) {
		c.LinkExistingUsers = &config.LinkExistingUsers{RequireExistingOrgMembership: true}
	}})
	e.signUp(t, "owner@a.com")
	orgID := e.createOrg(t, "link")
	token := e.mustToken(t, "okta", orgID)
	e.freshBrowser()
	insider := e.signUp(t, "insider@a.com")
	e.signUp(t, "outsider@a.com")
	if _, err := e.org.OrganizationStore().AddMember(context.Background(), orgID, insider, "member"); err != nil {
		t.Fatal(err)
	}
	if r := e.scimDo(t, http.MethodPost, "/scim/v2/Users", token, userBody("insider@a.com", nil)); r.Status != http.StatusCreated || resource(t, r)["id"] != insider {
		t.Fatalf("insider link %d %s", r.Status, r.Body)
	}
	scimErr(t, e.scimDo(t, http.MethodPost, "/scim/v2/Users", token, userBody("outsider@a.com", nil)), http.StatusConflict, "User already exists", "uniqueness")
}
