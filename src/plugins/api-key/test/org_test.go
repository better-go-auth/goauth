package test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	goauth "github.com/better-go-auth/goauth"
	apikey "github.com/better-go-auth/goauth/src/plugins/api-key"
	apikeyconfig "github.com/better-go-auth/goauth/src/plugins/api-key/config"
	"github.com/better-go-auth/goauth/src/plugins/org"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	orgdtos "github.com/better-go-auth/goauth/src/plugins/org/dtos"
	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
	"github.com/better-go-auth/goauth/src/providers/access"
)

// lazyOrg resolves the organization plugin when first used (it is built inside the server options).
type lazyOrg struct{ get func() *org.OrgPlugin }

func (l lazyOrg) MemberRole(ctx context.Context, orgID, userID string) (string, bool, error) {
	return apikey.OrganizationFrom(l.get()).MemberRole(ctx, orgID, userID)
}

func (l lazyOrg) HasPermission(ctx context.Context, orgID, role string, req access.Request) (bool, error) {
	return apikey.OrganizationFrom(l.get()).HasPermission(ctx, orgID, role, req)
}

func (l lazyOrg) CreatorRole() string { return apikey.OrganizationFrom(l.get()).CreatorRole() }

func TestOrganizationKeys(t *testing.T) {
	var orgPlugin *org.OrgPlugin
	h := newHarness(t,
		withConfigs(
			apikeyconfig.Configuration{ConfigID: "default"},
			apikeyconfig.Configuration{ConfigID: "org", References: apikeyconfig.ReferencesOrganization, EnableSessionForAPIKeys: true},
		),
		withPluginOptions(apikey.WithOrganization(lazyOrg{get: func() *org.OrgPlugin { return orgPlugin }})),
		withServer(func(o *goauth.GoAuthOptions) {
			// better-auth access control with an apiKey resource: members may read organization keys
			ac := access.NewAccessControl(orgconfig.DefaultAC.Statements().Merge(access.Statements{"apiKey": {"create", "read", "update", "delete"}}))
			roles := orgconfig.DefaultRoles()
			roles["member"] = ac.NewRole(roles["member"].Statements().Merge(access.Statements{"apiKey": {"read"}}))
			p, err := org.NewWithGorm(o.Conn, orgconfig.OrgConfig{}, org.WithAccessControl(ac), org.WithRoles(roles))
			if err != nil {
				t.Fatal(err)
			}
			orgPlugin = p
			o.Plugins = append(o.Plugins, p)
		}),
	)
	ctx := context.Background()
	owner, member, outsider := h.signUp(t), h.signUp(t), h.signUp(t)
	// Step 1: an organization with an owner and a member
	o, err := orgPlugin.Service().CreateOrganization(ctx, owner.ID, orgdtos.CreateOrgInput{Name: "Acme", Slug: "acme-keys"})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := orgPlugin.Service().InviteMember(ctx, owner.ID, orgdtos.InviteMemberInput{OrganizationID: o.ID, Email: member.Email, Role: orgmodels.OrgRoleMember})
	if err != nil {
		t.Fatal(err)
	}
	if err := orgPlugin.Service().AcceptInvitation(ctx, inv.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	// Step 2: the owner (creator role) creates an organization key
	expectError(t, h.Post(t, "/api/auth/api-key/create", map[string]any{"configId": "org"}, owner.as()), 400, "ORGANIZATION_ID_REQUIRED",
		"Organization ID is required for organization-owned API keys.")
	k := h.createKey(t, owner, map[string]any{"configId": "org", "organizationId": o.ID})
	if k.ReferenceID != o.ID || k.ConfigID != "org" {
		t.Fatalf("org key = %+v", k)
	}
	userKey := h.createKey(t, owner, nil)
	// Step 3: a member may read (apiKey:read) but not create / update / delete
	expectError(t, h.Post(t, "/api/auth/api-key/create", map[string]any{"configId": "org", "organizationId": o.ID}, member.as()),
		http.StatusForbidden, "INSUFFICIENT_API_KEY_PERMISSIONS", "You do not have permission to perform this action on organization API keys.")
	var list struct {
		APIKeys []keyBody `json:"apiKeys"`
		Total   int       `json:"total"`
	}
	expectOK(t, h.Get(t, "/api/auth/api-key/list?organizationId="+o.ID, member.as()), &list)
	if list.Total != 1 || list.APIKeys[0].ID != k.ID {
		t.Fatalf("org list = %+v", list)
	}
	expectOK(t, h.Get(t, "/api/auth/api-key/get?configId=org&id="+k.ID, member.as()), nil)
	expectError(t, h.Post(t, "/api/auth/api-key/update", map[string]any{"configId": "org", "keyId": k.ID, "name": "x"}, member.as()),
		http.StatusForbidden, "INSUFFICIENT_API_KEY_PERMISSIONS")
	expectError(t, h.Post(t, "/api/auth/api-key/delete", map[string]any{"configId": "org", "keyId": k.ID}, member.as()),
		http.StatusForbidden, "INSUFFICIENT_API_KEY_PERMISSIONS")
	// Step 4: outsiders are not members
	expectError(t, h.Get(t, "/api/auth/api-key/list?organizationId="+o.ID, outsider.as()), http.StatusForbidden, "USER_NOT_MEMBER_OF_ORGANIZATION",
		"You are not a member of the organization that owns this API key.")
	expectError(t, h.Get(t, "/api/auth/api-key/get?configId=org&id="+k.ID, outsider.as()), http.StatusForbidden, "USER_NOT_MEMBER_OF_ORGANIZATION")
	// Step 5: user lists do not contain organization keys and vice versa
	expectOK(t, h.Get(t, "/api/auth/api-key/list", owner.as()), &list)
	if list.Total != 1 || list.APIKeys[0].ID != userKey.ID {
		t.Fatalf("user list = %+v", list)
	}
	// Step 6: organization keys verify, but never become sessions
	if !h.verify(t, k.Key, nil).Valid {
		t.Fatal("org key should verify")
	}
	expectError(t, h.Get(t, "/api/auth/get-session", keyHeader(k.Key)), http.StatusUnauthorized, "INVALID_REFERENCE_ID_FROM_API_KEY")
	// the host middleware accepts organization keys without a session (the key is in the context)
	mw := h.plugin.HTTPMiddleware(apikey.MiddlewareOptions{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, ok := apikey.FromContext(r.Context())
		_, hasSession := apikey.SessionFromContext(r.Context())
		if !ok || key.ReferenceID != o.ID || hasSession {
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/app", nil)
	req.Header.Set("x-api-key", k.Key)
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("host middleware with an organization key: %d %s", rec.Code, rec.Body)
	}
	// Step 7: the owner deletes it; server-side creation names the acting user
	expectOK(t, h.Post(t, "/api/auth/api-key/update", map[string]any{"configId": "org", "keyId": k.ID, "name": "renamed"}, owner.as()), nil)
	expectOK(t, h.Post(t, "/api/auth/api-key/delete", map[string]any{"configId": "org", "keyId": k.ID}, owner.as()), nil)
	_, err = h.plugin.CreateAPIKey(ctx, apikey.CreateAPIKeyInput{ConfigID: "org", OrganizationID: &o.ID})
	expectAuthErr(t, err, http.StatusUnauthorized, "UNAUTHORIZED_SESSION")
	sk, err := h.plugin.CreateAPIKey(ctx, apikey.CreateAPIKeyInput{ConfigID: "org", OrganizationID: &o.ID, UserID: &owner.ID})
	if err != nil || sk.ReferenceID != o.ID {
		t.Fatalf("server org key = %+v, %v", sk, err)
	}
}

// TestOrganizationDefaultRolesDenyMembers checks better-auth's default member role (no apiKey statement)
// cannot read organization keys.
func TestOrganizationDefaultRolesDenyMembers(t *testing.T) {
	var orgPlugin *org.OrgPlugin
	h := newHarness(t,
		withConfigs(apikeyconfig.Configuration{References: apikeyconfig.ReferencesOrganization}),
		withPluginOptions(apikey.WithOrganization(lazyOrg{get: func() *org.OrgPlugin { return orgPlugin }})),
		withServer(func(o *goauth.GoAuthOptions) {
			p, err := org.NewWithGorm(o.Conn, orgconfig.OrgConfig{})
			if err != nil {
				t.Fatal(err)
			}
			orgPlugin = p
			o.Plugins = append(o.Plugins, p)
		}),
	)
	ctx := context.Background()
	owner, member := h.signUp(t), h.signUp(t)
	o, err := orgPlugin.Service().CreateOrganization(ctx, owner.ID, orgdtos.CreateOrgInput{Name: "Beta", Slug: "beta-keys"})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := orgPlugin.Service().InviteMember(ctx, owner.ID, orgdtos.InviteMemberInput{OrganizationID: o.ID, Email: member.Email, Role: orgmodels.OrgRoleMember})
	if err != nil {
		t.Fatal(err)
	}
	if err := orgPlugin.Service().AcceptInvitation(ctx, inv.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	h.createKey(t, owner, map[string]any{"organizationId": o.ID})
	expectError(t, h.Get(t, "/api/auth/api-key/list?organizationId="+o.ID, member.as()), http.StatusForbidden, "INSUFFICIENT_API_KEY_PERMISSIONS")
}

func TestOrganizationKeysWithoutOrgPlugin(t *testing.T) {
	h := newHarness(t, withConfigs(apikeyconfig.Configuration{References: apikeyconfig.ReferencesOrganization}))
	u := h.signUp(t)
	expectError(t, h.Post(t, "/api/auth/api-key/create", map[string]any{"organizationId": "org-1"}, u.as()), http.StatusInternalServerError,
		"ORGANIZATION_PLUGIN_REQUIRED")
	expectError(t, h.Get(t, "/api/auth/api-key/list?organizationId=org-1", u.as()), http.StatusInternalServerError, "ORGANIZATION_PLUGIN_REQUIRED")
}
