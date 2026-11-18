package org_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	coremodels "github.com/better-go-auth/goauth/src/models"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	orgdtos "github.com/better-go-auth/goauth/src/plugins/org/dtos"
	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/stretchr/testify/require"
)

// baOrgEnv is a server with the org plugin (teams on, no default team) and helpers for better-auth route tests.
type baOrgEnv struct {
	t   *testing.T
	env *helpers.TestEnv
}

func newBAOrgEnv(t *testing.T, cfg orgconfig.OrgConfig) *baOrgEnv {
	t.Helper()
	env, _ := setupTeamsEnv(t, cfg)
	return &baOrgEnv{t: t, env: env}
}

// teamsCfg enables teams without a default team.
func teamsCfg() orgconfig.OrgConfig {
	off := false
	return orgconfig.OrgConfig{Teams: &orgconfig.TeamsConfig{
		Enabled: true, DefaultTeam: &orgconfig.DefaultTeamConfig{Enabled: &off}, AllowRemovingAllTeams: true,
	}}
}

// user creates a verified user with a session and returns its ID and Authorization header value.
func (e *baOrgEnv) user(email string) (string, string) {
	e.t.Helper()
	id, hdr := setupOrgHTTPUser(e.t, e.env, email, "", "")
	return id, hdr["Authorization"]
}

// do sends a JSON request and returns the recorder.
func (e *baOrgEnv) do(method, path string, body any, auth string) *httptest.ResponseRecorder {
	e.t.Helper()
	return doOrgHTTP(e.t, e.env.Mux, method, path, body, auth)
}

// expect asserts status and, when code is set, the better-auth error code.
func (e *baOrgEnv) expect(rec *httptest.ResponseRecorder, status int, code string) {
	e.t.Helper()
	require.Equal(e.t, status, rec.Code, rec.Body.String())
	if code != "" {
		var body struct {
			Code string `json:"code"`
		}
		require.NoError(e.t, json.Unmarshal(rec.Body.Bytes(), &body), rec.Body.String())
		require.Equal(e.t, code, body.Code, rec.Body.String())
	}
}

// createOrg creates an organization through the API (it becomes the caller's active organization).
func (e *baOrgEnv) createOrg(auth, name, slug string) orgdtos.CreatedOrgResponse {
	e.t.Helper()
	rec := e.do(http.MethodPost, "/api/auth/organization/create", map[string]any{"name": name, "slug": slug}, auth)
	e.expect(rec, http.StatusOK, "")
	var org orgdtos.CreatedOrgResponse
	require.NoError(e.t, json.Unmarshal(rec.Body.Bytes(), &org))
	return org
}

// addMember inserts a membership row directly.
func (e *baOrgEnv) addMember(orgID, userID, role string) *orgmodels.Member {
	e.t.Helper()
	now := coremodels.TimeNow()
	m := &orgmodels.Member{
		Base:           coremodels.Base{ID: coremodels.NewID(), CreatedAt: now, UpdatedAt: now},
		OrganizationID: orgID, UserID: userID, Role: orgmodels.OrgMemberRole(role),
	}
	require.NoError(e.t, e.env.DB.Create(m).Error)
	return m
}

// setActive makes orgID the caller's active organization.
func (e *baOrgEnv) setActive(auth, orgID string) {
	e.t.Helper()
	e.expect(e.do(http.MethodPost, "/api/auth/organization/set-active", map[string]any{"organizationId": orgID}, auth), http.StatusOK, "")
}

// jsonKeys returns the sorted keys of a JSON object.
func jsonKeys(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	var m map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &m))
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TestBetterAuthRoute_GetActiveMember covers GET /organization/get-active-member.
func TestBetterAuthRoute_GetActiveMember(t *testing.T) {
	e := newBAOrgEnv(t, teamsCfg())
	ownerID, owner := e.user("gam-owner@example.com")
	memberID, member := e.user("gam-member@example.com")
	_, outsider := e.user("gam-outsider@example.com")
	org := e.createOrg(owner, "Active Member Org", "active-member-org")
	m := e.addMember(org.ID, memberID, "admin")

	// Step 1: unauthenticated → 401
	e.expect(e.do(http.MethodGet, "/api/auth/organization/get-active-member", nil, ""), http.StatusUnauthorized, "")

	// Step 2: no active organization → 400 NO_ACTIVE_ORGANIZATION
	e.expect(e.do(http.MethodGet, "/api/auth/organization/get-active-member", nil, outsider), http.StatusBadRequest, "NO_ACTIVE_ORGANIZATION")
	e.expect(e.do(http.MethodGet, "/api/auth/organization/get-active-member", nil, member), http.StatusBadRequest, "NO_ACTIVE_ORGANIZATION")

	// Step 3: the creator's membership, with better-auth's member.user shape {id, name, email, image}
	rec := e.do(http.MethodGet, "/api/auth/organization/get-active-member", nil, owner)
	e.expect(rec, http.StatusOK, "")
	require.NotContains(t, rec.Body.String(), "$schema")
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	require.Equal(t, []string{"createdAt", "id", "organizationId", "role", "user", "userId"}, jsonKeys(t, rec.Body.Bytes()))
	require.Equal(t, []string{"email", "id", "image", "name"}, jsonKeys(t, raw["user"]))
	var got orgdtos.MemberResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, ownerID, got.UserID)
	require.Equal(t, org.ID, got.OrganizationID)
	require.Equal(t, "owner", got.Role)
	require.Equal(t, "gam-owner@example.com", got.User.Email)

	// Step 4: a second member activates the organization
	e.setActive(member, org.ID)
	rec = e.do(http.MethodGet, "/api/auth/organization/get-active-member", nil, member)
	e.expect(rec, http.StatusOK, "")
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, m.ID, got.ID)
	require.Equal(t, "admin", got.Role)

	// Step 5: a member removed behind the session's back → 400 MEMBER_NOT_FOUND
	require.NoError(t, e.env.DB.Delete(&orgmodels.Member{}, "id = ?", m.ID).Error)
	e.expect(e.do(http.MethodGet, "/api/auth/organization/get-active-member", nil, member), http.StatusBadRequest, "MEMBER_NOT_FOUND")
}

// TestBetterAuthRoute_GetActiveMemberRole covers GET /organization/get-active-member-role.
func TestBetterAuthRoute_GetActiveMemberRole(t *testing.T) {
	e := newBAOrgEnv(t, teamsCfg())
	ownerID, owner := e.user("gamr-owner@example.com")
	memberID, member := e.user("gamr-member@example.com")
	outsiderID, outsider := e.user("gamr-outsider@example.com")
	org := e.createOrg(owner, "Role Org", "role-org")
	e.addMember(org.ID, memberID, "admin,member")
	const path = "/api/auth/organization/get-active-member-role"

	// Step 1: unauthenticated → 401
	e.expect(e.do(http.MethodGet, path, nil, ""), http.StatusUnauthorized, "")

	// Step 2: the caller's role in the active organization
	rec := e.do(http.MethodGet, path, nil, owner)
	e.expect(rec, http.StatusOK, "")
	require.JSONEq(t, `{"role":"owner"}`, rec.Body.String())

	// Step 3: no active organization and no query → 400 NO_ACTIVE_ORGANIZATION
	e.expect(e.do(http.MethodGet, path, nil, member), http.StatusBadRequest, "NO_ACTIVE_ORGANIZATION")

	// Step 4: organizationId / organizationSlug select the organization (multi-role stays comma-joined)
	rec = e.do(http.MethodGet, path+"?organizationId="+org.ID, nil, member)
	e.expect(rec, http.StatusOK, "")
	require.JSONEq(t, `{"role":"admin,member"}`, rec.Body.String())
	rec = e.do(http.MethodGet, path+"?organizationSlug=role-org", nil, member)
	e.expect(rec, http.StatusOK, "")
	require.JSONEq(t, `{"role":"admin,member"}`, rec.Body.String())
	e.expect(e.do(http.MethodGet, path+"?organizationSlug=missing-slug", nil, member), http.StatusBadRequest, "ORGANIZATION_NOT_FOUND")

	// Step 5: another member's role by userId
	rec = e.do(http.MethodGet, path+"?organizationId="+org.ID+"&userId="+ownerID, nil, member)
	e.expect(rec, http.StatusOK, "")
	require.JSONEq(t, `{"role":"owner"}`, rec.Body.String())

	// Step 6: userId of a non-member and callers outside the organization → 403 YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION
	e.expect(e.do(http.MethodGet, path+"?userId="+outsiderID, nil, owner), http.StatusForbidden, "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION")
	e.expect(e.do(http.MethodGet, path+"?organizationId="+org.ID, nil, outsider), http.StatusForbidden, "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION")
	e.expect(e.do(http.MethodGet, path+"?organizationId="+org.ID+"&userId="+ownerID, nil, outsider), http.StatusForbidden, "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION")
}

// TestBetterAuthRoute_ListUserTeams covers GET /organization/list-user-teams.
func TestBetterAuthRoute_ListUserTeams(t *testing.T) {
	e := newBAOrgEnv(t, teamsCfg())
	_, owner := e.user("lut-owner@example.com")
	memberID, member := e.user("lut-member@example.com")
	const path = "/api/auth/organization/list-user-teams"

	orgA := e.createOrg(owner, "Teams A", "teams-a")
	e.addMember(orgA.ID, memberID, "member")
	mkTeam := func(orgID, name string) orgdtos.TeamResponse {
		rec := e.do(http.MethodPost, "/api/auth/organization/create-team", map[string]any{"name": name, "organizationId": orgID}, owner)
		e.expect(rec, http.StatusOK, "")
		var team orgdtos.TeamResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &team))
		return team
	}
	t1, _ := mkTeam(orgA.ID, "Alpha"), mkTeam(orgA.ID, "Beta")
	orgB := e.createOrg(owner, "Teams B", "teams-b")
	e.addMember(orgB.ID, memberID, "member")
	t3 := mkTeam(orgB.ID, "Gamma")

	// Step 1: unauthenticated → 401
	e.expect(e.do(http.MethodGet, path, nil, ""), http.StatusUnauthorized, "")

	// Step 2: no team memberships → empty array (not null)
	rec := e.do(http.MethodGet, path, nil, member)
	e.expect(rec, http.StatusOK, "")
	require.JSONEq(t, `[]`, rec.Body.String())

	// Step 3: teams of several organizations, with better-auth's team shape
	for _, team := range []orgdtos.TeamResponse{t1, t3} {
		e.expect(e.do(http.MethodPost, "/api/auth/organization/add-team-member", map[string]any{
			"teamId": team.ID, "userId": memberID, "organizationId": team.OrganizationID,
		}, owner), http.StatusOK, "")
	}
	rec = e.do(http.MethodGet, path, nil, member)
	e.expect(rec, http.StatusOK, "")
	var teams []json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &teams))
	require.Len(t, teams, 2)
	require.Equal(t, []string{"createdAt", "id", "name", "organizationId", "updatedAt"}, jsonKeys(t, teams[0]))
	ids := map[string]bool{}
	for _, raw := range teams {
		var team orgdtos.TeamResponse
		require.NoError(t, json.Unmarshal(raw, &team))
		ids[team.ID] = true
	}
	require.True(t, ids[t1.ID] && ids[t3.ID], rec.Body.String())

	// Step 4: teams of an organization the user is no longer a member of are dropped
	require.NoError(t, e.env.DB.Delete(&orgmodels.Member{}, "organization_id = ? AND user_id = ?", orgB.ID, memberID).Error)
	rec = e.do(http.MethodGet, path, nil, member)
	e.expect(rec, http.StatusOK, "")
	var after []orgdtos.TeamResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &after))
	require.Len(t, after, 1)
	require.Equal(t, t1.ID, after[0].ID)

	// Step 5: teams disabled → 404 (better-auth does not mount the team routes)
	off := newBAOrgEnv(t, orgconfig.OrgConfig{})
	_, someone := off.user("lut-off@example.com")
	off.expect(off.do(http.MethodGet, path, nil, someone), http.StatusNotFound, "")
}

// TestBetterAuthRoutes_OrganizationAudit covers the better-auth shapes, statuses and errors fixed in the org
// route audit (create, check-slug, get-full-organization, list, set-active, update, delete).
func TestBetterAuthRoutes_OrganizationAudit(t *testing.T) {
	e := newBAOrgEnv(t, teamsCfg())
	ownerID, owner := e.user("audit-owner@example.com")
	memberID, member := e.user("audit-member@example.com")
	_, outsider := e.user("audit-outsider@example.com")

	// Step 1: create: 200, the creator's raw membership in members, metadata object round trip
	rec := e.do(http.MethodPost, "/api/auth/organization/create", map[string]any{
		"name": "Audit Org", "slug": "audit-org", "metadata": map[string]any{"plan": "pro", "seats": 5},
	}, owner)
	e.expect(rec, http.StatusOK, "")
	require.NotContains(t, rec.Body.String(), "$schema")
	var org orgdtos.CreatedOrgResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &org))
	require.Equal(t, map[string]any{"plan": "pro", "seats": float64(5)}, org.Metadata)
	require.Len(t, org.Members, 1)
	require.Equal(t, ownerID, org.Members[0].UserID)
	require.Nil(t, org.Members[0].User, "create returns the raw member row")
	e.expect(e.do(http.MethodPost, "/api/auth/organization/create", map[string]any{"name": "Dup", "slug": "audit-org"}, owner), http.StatusBadRequest, "ORGANIZATION_ALREADY_EXISTS")
	e.addMember(org.ID, memberID, "member")

	// Step 2: check-slug: taken → 400 ORGANIZATION_SLUG_ALREADY_TAKEN, free → {status: true}
	e.expect(e.do(http.MethodPost, "/api/auth/organization/check-slug", map[string]any{"slug": "audit-org"}, owner), http.StatusBadRequest, "ORGANIZATION_SLUG_ALREADY_TAKEN")
	rec = e.do(http.MethodPost, "/api/auth/organization/check-slug", map[string]any{"slug": "audit-free"}, owner)
	e.expect(rec, http.StatusOK, "")
	require.JSONEq(t, `{"status":true}`, rec.Body.String())

	// Step 3: get-full-organization: null without org, members/invitations/teams, errors
	rec = e.do(http.MethodGet, "/api/auth/organization/get-full-organization", nil, outsider)
	e.expect(rec, http.StatusOK, "")
	require.Equal(t, "null", string(bytesTrim(rec.Body.Bytes())))
	rec = e.do(http.MethodGet, "/api/auth/organization/get-full-organization?organizationSlug=audit-org", nil, owner)
	e.expect(rec, http.StatusOK, "")
	var full orgdtos.FullOrgResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &full))
	require.Equal(t, org.ID, full.ID)
	require.Len(t, full.Members, 2)
	require.NotNil(t, full.Members[0].User)
	require.NotNil(t, full.Invitations)
	require.NotNil(t, full.Teams)
	rec = e.do(http.MethodGet, "/api/auth/organization/get-full-organization?membersLimit=1", nil, owner)
	e.expect(rec, http.StatusOK, "")
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &full))
	require.Len(t, full.Members, 1, "membersLimit caps the members")
	e.expect(e.do(http.MethodGet, "/api/auth/organization/get-full-organization?organizationId="+org.ID, nil, outsider), http.StatusForbidden, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
	e.expect(e.do(http.MethodGet, "/api/auth/organization/get-full-organization?organizationId=missing", nil, owner), http.StatusBadRequest, "ORGANIZATION_NOT_FOUND")

	// Step 4: list is an array
	rec = e.do(http.MethodGet, "/api/auth/organization/list", nil, owner)
	e.expect(rec, http.StatusOK, "")
	var orgs []orgdtos.OrgResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &orgs))
	require.Len(t, orgs, 1)

	// Step 5: set-active returns the organization, null unsets, non-members are refused
	rec = e.do(http.MethodPost, "/api/auth/organization/set-active", map[string]any{"organizationSlug": "audit-org"}, member)
	e.expect(rec, http.StatusOK, "")
	var active orgdtos.OrgResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &active))
	require.Equal(t, org.ID, active.ID)
	rec = e.do(http.MethodPost, "/api/auth/organization/set-active", map[string]any{"organizationId": nil}, member)
	e.expect(rec, http.StatusOK, "")
	require.Equal(t, "null", string(bytesTrim(rec.Body.Bytes())))
	e.expect(e.do(http.MethodGet, "/api/auth/organization/get-active-member", nil, member), http.StatusBadRequest, "NO_ACTIVE_ORGANIZATION")
	e.expect(e.do(http.MethodPost, "/api/auth/organization/set-active", map[string]any{"organizationId": org.ID}, outsider), http.StatusForbidden, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
	e.expect(e.do(http.MethodPost, "/api/auth/organization/set-active", map[string]any{"organizationSlug": "nope"}, outsider), http.StatusBadRequest, "ORGANIZATION_NOT_FOUND")

	// Step 6: update: permission and membership errors, slug conflicts, metadata
	e.expect(e.do(http.MethodPost, "/api/auth/organization/update", map[string]any{"organizationId": org.ID, "data": map[string]any{"name": "X"}}, member), http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION")
	e.expect(e.do(http.MethodPost, "/api/auth/organization/update", map[string]any{"organizationId": org.ID, "data": map[string]any{"name": "X"}}, outsider), http.StatusBadRequest, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
	e.createOrg(owner, "Other", "audit-other")
	e.expect(e.do(http.MethodPost, "/api/auth/organization/update", map[string]any{"organizationId": org.ID, "data": map[string]any{"slug": "audit-other"}}, owner), http.StatusBadRequest, "ORGANIZATION_SLUG_ALREADY_TAKEN")
	rec = e.do(http.MethodPost, "/api/auth/organization/update", map[string]any{"organizationId": org.ID, "data": map[string]any{"metadata": map[string]any{"plan": "team"}}}, owner)
	e.expect(rec, http.StatusOK, "")
	var updated orgdtos.OrgResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updated))
	require.Equal(t, map[string]any{"plan": "team"}, updated.Metadata)

	// Step 7: delete: permission errors, then the deleted organization is returned
	e.expect(e.do(http.MethodPost, "/api/auth/organization/delete", map[string]any{"organizationId": org.ID}, member), http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION")
	e.expect(e.do(http.MethodPost, "/api/auth/organization/delete", map[string]any{"organizationId": org.ID}, outsider), http.StatusBadRequest, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
	rec = e.do(http.MethodPost, "/api/auth/organization/delete", map[string]any{"organizationId": org.ID}, owner)
	e.expect(rec, http.StatusOK, "")
	var deleted orgdtos.OrgResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &deleted))
	require.Equal(t, org.ID, deleted.ID)
}

// TestBetterAuthRoutes_InvitationAudit covers invite-member, get/list/accept/reject/cancel invitation shapes and errors.
func TestBetterAuthRoutes_InvitationAudit(t *testing.T) {
	e := newBAOrgEnv(t, teamsCfg())
	_, owner := e.user("inv-owner@example.com")
	adminID, admin := e.user("inv-admin@example.com")
	memberID, member := e.user("inv-member@example.com")
	_, invitee := e.user("inv-invitee@example.com")
	_, invitee2 := e.user("inv-invitee2@example.com")
	org := e.createOrg(owner, "Invite Org", "invite-org")
	e.addMember(org.ID, adminID, "admin")
	e.addMember(org.ID, memberID, "member")
	invite := func(auth, email, role string) *httptest.ResponseRecorder {
		return e.do(http.MethodPost, "/api/auth/organization/invite-member", map[string]any{"organizationId": org.ID, "email": email, "role": role}, auth)
	}

	// Step 1: permission errors
	e.expect(invite(member, "x@example.com", "member"), http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION")
	e.expect(invite(admin, "x@example.com", "owner"), http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE")

	// Step 2: invite-member → 200 with the invitation row (teamId null, no enrichment)
	rec := invite(admin, "inv-invitee@example.com", "member")
	e.expect(rec, http.StatusOK, "")
	require.Equal(t, []string{"createdAt", "email", "expiresAt", "id", "inviterId", "organizationId", "role", "status", "teamId"}, jsonKeys(t, rec.Body.Bytes()))
	var inv orgdtos.InvitationResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &inv))
	e.expect(invite(admin, "inv-invitee@example.com", "member"), http.StatusBadRequest, "USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION")

	// Step 3: list-invitations is an array, readable by any member
	rec = e.do(http.MethodGet, "/api/auth/organization/list-invitations?organizationId="+org.ID, nil, member)
	e.expect(rec, http.StatusOK, "")
	var list []orgdtos.InvitationResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	require.Len(t, list, 1)
	e.expect(e.do(http.MethodGet, "/api/auth/organization/list-invitations?organizationId="+org.ID, nil, invitee), http.StatusForbidden, "")

	// Step 4: get-invitation: only the recipient, enriched with organization and inviter email
	e.expect(e.do(http.MethodGet, "/api/auth/organization/get-invitation?id="+inv.ID, nil, owner), http.StatusForbidden, "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION")
	rec = e.do(http.MethodGet, "/api/auth/organization/get-invitation?id="+inv.ID, nil, invitee)
	e.expect(rec, http.StatusOK, "")
	var details orgdtos.InvitationDetailsResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &details))
	require.Equal(t, "inv-admin@example.com", details.InviterEmail)
	require.Equal(t, "Invite Org", *details.OrganizationName)
	require.Equal(t, "invite-org", *details.OrganizationSlug)
	e.expect(e.do(http.MethodGet, "/api/auth/organization/get-invitation?id=missing", nil, invitee), http.StatusBadRequest, "")

	// Step 5: list-user-invitations is an array with organizationName
	rec = e.do(http.MethodGet, "/api/auth/organization/list-user-invitations", nil, invitee)
	e.expect(rec, http.StatusOK, "")
	var inbox []orgdtos.InvitationResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &inbox))
	require.Len(t, inbox, 1)
	require.Equal(t, "Invite Org", *inbox[0].OrganizationName)
	e.expect(e.do(http.MethodGet, "/api/auth/organization/list-user-invitations?email=inv-invitee@example.com", nil, invitee), http.StatusBadRequest, "")

	// Step 6: reject → {invitation: rejected, member: null}; a second reject → 400 INVITATION_NOT_FOUND
	e.expect(e.do(http.MethodPost, "/api/auth/organization/reject-invitation", map[string]any{"invitationId": inv.ID}, owner), http.StatusForbidden, "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION")
	rec = e.do(http.MethodPost, "/api/auth/organization/reject-invitation", map[string]any{"invitationId": inv.ID}, invitee)
	e.expect(rec, http.StatusOK, "")
	require.JSONEq(t, `null`, string(mustField(t, rec.Body.Bytes(), "member")))
	var rejected orgdtos.InvitationResultResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &rejected))
	require.Equal(t, "rejected", rejected.Invitation.Status)
	e.expect(e.do(http.MethodPost, "/api/auth/organization/reject-invitation", map[string]any{"invitationId": inv.ID}, invitee), http.StatusBadRequest, "INVITATION_NOT_FOUND")
	e.expect(e.do(http.MethodPost, "/api/auth/organization/accept-invitation", map[string]any{"invitationId": inv.ID}, invitee), http.StatusBadRequest, "INVITATION_NOT_FOUND")

	// Step 7: cancel → the canceled invitation; plain members may not cancel
	rec = invite(owner, "inv-invitee2@example.com", "admin")
	e.expect(rec, http.StatusOK, "")
	var inv2 orgdtos.InvitationResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &inv2))
	e.expect(e.do(http.MethodPost, "/api/auth/organization/cancel-invitation", map[string]any{"invitationId": inv2.ID}, member), http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION")
	rec = e.do(http.MethodPost, "/api/auth/organization/cancel-invitation", map[string]any{"invitationId": inv2.ID}, owner)
	e.expect(rec, http.StatusOK, "")
	var canceled orgdtos.InvitationResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &canceled))
	require.Equal(t, "canceled", canceled.Status)

	// Step 8: accept → {invitation, member}; the organization becomes active
	rec = invite(owner, "inv-invitee2@example.com", "admin")
	e.expect(rec, http.StatusOK, "")
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &inv2))
	rec = e.do(http.MethodPost, "/api/auth/organization/accept-invitation", map[string]any{"invitationId": inv2.ID}, invitee2)
	e.expect(rec, http.StatusOK, "")
	var accepted orgdtos.InvitationResultResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &accepted))
	require.Equal(t, "accepted", accepted.Invitation.Status)
	require.Equal(t, "admin", accepted.Member.Role)
	rec = e.do(http.MethodGet, "/api/auth/organization/get-active-member-role", nil, invitee2)
	e.expect(rec, http.StatusOK, "")
	require.JSONEq(t, `{"role":"admin"}`, rec.Body.String())
}

// TestBetterAuthRoutes_MemberAudit covers list-members, update-member-role, remove-member and leave.
func TestBetterAuthRoutes_MemberAudit(t *testing.T) {
	e := newBAOrgEnv(t, teamsCfg())
	ownerID, owner := e.user("mem-owner@example.com")
	adminID, admin := e.user("mem-admin@example.com")
	memberID, member := e.user("mem-member@example.com")
	_, outsider := e.user("mem-outsider@example.com")
	org := e.createOrg(owner, "Member Org", "member-org")
	adminRow := e.addMember(org.ID, adminID, "admin")
	memberRow := e.addMember(org.ID, memberID, "member")
	extraID, _ := e.user("mem-extra@example.com")
	e.addMember(org.ID, extraID, "member")
	ownerRow := struct{ ID string }{}
	require.NoError(t, e.env.DB.Model(&orgmodels.Member{}).Select("id").Where("organization_id = ? AND user_id = ?", org.ID, ownerID).Take(&ownerRow).Error)

	// Step 1: list-members: {members (user = id/name/email/image), total}, pagination, membership errors
	rec := e.do(http.MethodGet, "/api/auth/organization/list-members?organizationId="+org.ID+"&limit=2&sortBy=createdAt&sortDirection=asc", nil, member)
	e.expect(rec, http.StatusOK, "")
	var page struct {
		Members []json.RawMessage `json:"members"`
		Total   int64             `json:"total"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
	require.Len(t, page.Members, 2)
	require.EqualValues(t, 4, page.Total)
	var first map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(page.Members[0], &first))
	require.Equal(t, []string{"email", "id", "image", "name"}, jsonKeys(t, first["user"]))
	e.expect(e.do(http.MethodGet, "/api/auth/organization/list-members?organizationSlug=member-org", nil, outsider), http.StatusForbidden, "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION")
	e.expect(e.do(http.MethodGet, "/api/auth/organization/list-members", nil, outsider), http.StatusBadRequest, "NO_ACTIVE_ORGANIZATION")

	// Step 2: update-member-role rules
	upd := func(auth, memberID string, role any) *httptest.ResponseRecorder {
		return e.do(http.MethodPost, "/api/auth/organization/update-member-role", map[string]any{"organizationId": org.ID, "memberId": memberID, "role": role}, auth)
	}
	e.expect(upd(member, adminRow.ID, "member"), http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER")
	e.expect(upd(admin, memberRow.ID, "owner"), http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER")
	e.expect(upd(admin, ownerRow.ID, "member"), http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER")
	e.expect(upd(owner, ownerRow.ID, "admin"), http.StatusBadRequest, "YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER")
	e.expect(upd(outsider, memberRow.ID, "admin"), http.StatusBadRequest, "MEMBER_NOT_FOUND")
	e.expect(upd(owner, "missing", "admin"), http.StatusBadRequest, "MEMBER_NOT_FOUND")
	rec = upd(admin, memberRow.ID, []string{"admin", "member"})
	e.expect(rec, http.StatusOK, "")
	var updated map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updated))
	require.JSONEq(t, `"admin,member"`, string(updated["role"]), "array roles are comma-joined")
	require.NotContains(t, updated, "user", "update returns the raw member row")
	e.expect(upd(owner, memberRow.ID, "owner"), http.StatusOK, "")

	// Step 3: remove-member: plain members get 401; owners need another owner; returns {member}
	e.expect(e.do(http.MethodPost, "/api/auth/organization/update-member-role", map[string]any{"organizationId": org.ID, "memberId": adminRow.ID, "role": "member"}, owner), http.StatusOK, "")
	e.expect(e.do(http.MethodPost, "/api/auth/organization/remove-member", map[string]any{"organizationId": org.ID, "memberIdOrEmail": "mem-owner@example.com"}, admin), http.StatusBadRequest, "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER")
	e.expect(e.do(http.MethodPost, "/api/auth/organization/remove-member", map[string]any{"organizationId": org.ID, "memberIdOrEmail": "mem-owner@example.com"}, outsider), http.StatusBadRequest, "MEMBER_NOT_FOUND")
	e.expect(e.do(http.MethodPost, "/api/auth/organization/remove-member", map[string]any{"organizationId": org.ID, "memberIdOrEmail": "nobody@example.com"}, owner), http.StatusBadRequest, "MEMBER_NOT_FOUND")
	// mem-member is a second owner now, so the first owner can be removed by them
	rec = e.do(http.MethodPost, "/api/auth/organization/remove-member", map[string]any{"organizationId": org.ID, "memberIdOrEmail": ownerRow.ID}, member)
	e.expect(rec, http.StatusOK, "")
	var removed orgdtos.RemovedMemberResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &removed))
	require.Equal(t, ownerRow.ID, removed.Member.ID)
	require.Nil(t, removed.Member.User, "lookup by id returns the member without its user")
	// a plain member (admin was demoted) may not remove others: 401, and the owner rules win for owners
	e.expect(e.do(http.MethodPost, "/api/auth/organization/remove-member", map[string]any{"organizationId": org.ID, "memberIdOrEmail": "mem-extra@example.com"}, admin), http.StatusUnauthorized, "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER")
	e.expect(e.do(http.MethodPost, "/api/auth/organization/remove-member", map[string]any{"organizationId": org.ID, "memberIdOrEmail": "mem-member@example.com"}, admin), http.StatusBadRequest, "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER")
	// by email, the removed member comes with its user
	rec = e.do(http.MethodPost, "/api/auth/organization/remove-member", map[string]any{"organizationId": org.ID, "memberIdOrEmail": "mem-extra@example.com"}, member)
	e.expect(rec, http.StatusOK, "")
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &removed))
	require.NotNil(t, removed.Member.User)
	require.Equal(t, "mem-extra@example.com", removed.Member.User.Email)

	// Step 4: leave returns the former membership; the last owner cannot leave
	e.expect(e.do(http.MethodPost, "/api/auth/organization/leave", map[string]any{"organizationId": org.ID}, member), http.StatusBadRequest, "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER")
	e.expect(e.do(http.MethodPost, "/api/auth/organization/leave", map[string]any{"organizationId": org.ID}, outsider), http.StatusBadRequest, "MEMBER_NOT_FOUND")
	rec = e.do(http.MethodPost, "/api/auth/organization/leave", map[string]any{"organizationId": org.ID}, admin)
	e.expect(rec, http.StatusOK, "")
	var left orgdtos.MemberResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &left))
	require.Equal(t, adminRow.ID, left.ID)
}

// TestBetterAuthRoutes_TeamAudit covers team route shapes and errors.
func TestBetterAuthRoutes_TeamAudit(t *testing.T) {
	e := newBAOrgEnv(t, teamsCfg())
	_, owner := e.user("team-owner@example.com")
	memberID, member := e.user("team-member@example.com")
	_, outsider := e.user("team-outsider@example.com")
	org := e.createOrg(owner, "Team Org", "team-org")
	e.addMember(org.ID, memberID, "member")

	// Step 1: create-team permission errors
	e.expect(e.do(http.MethodPost, "/api/auth/organization/create-team", map[string]any{"name": "X", "organizationId": org.ID}, member), http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION")
	rec := e.do(http.MethodPost, "/api/auth/organization/create-team", map[string]any{"name": "Core", "organizationId": org.ID}, owner)
	e.expect(rec, http.StatusOK, "")
	var team orgdtos.TeamResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &team))

	// Step 2: list-teams errors
	e.expect(e.do(http.MethodGet, "/api/auth/organization/list-teams?organizationId="+org.ID, nil, outsider), http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION")

	// Step 3: add-team-member is idempotent (better-auth's findOrCreateTeamMember)
	add := map[string]any{"teamId": team.ID, "userId": memberID, "organizationId": org.ID}
	rec = e.do(http.MethodPost, "/api/auth/organization/add-team-member", add, owner)
	e.expect(rec, http.StatusOK, "")
	var tm1, tm2 orgdtos.TeamMemberResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &tm1))
	rec = e.do(http.MethodPost, "/api/auth/organization/add-team-member", add, owner)
	e.expect(rec, http.StatusOK, "")
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &tm2))
	require.Equal(t, tm1.ID, tm2.ID)
	e.expect(e.do(http.MethodPost, "/api/auth/organization/add-team-member", add, member), http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER")

	// Step 4: list-team-members: no team → 400 YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM; non team member → 400
	e.expect(e.do(http.MethodGet, "/api/auth/organization/list-team-members", nil, member), http.StatusBadRequest, "YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM")
	e.expect(e.do(http.MethodGet, "/api/auth/organization/list-team-members?teamId="+team.ID, nil, owner), http.StatusBadRequest, "USER_IS_NOT_A_MEMBER_OF_THE_TEAM")
	e.expect(e.do(http.MethodGet, "/api/auth/organization/list-team-members?teamId=missing", nil, owner), http.StatusBadRequest, "TEAM_NOT_FOUND")

	// Step 5: set-active-team: team of the active organization only, returns the team, null unsets
	e.expect(e.do(http.MethodPost, "/api/auth/organization/set-active-team", map[string]any{"teamId": team.ID}, member), http.StatusBadRequest, "NO_ACTIVE_ORGANIZATION")
	e.setActive(member, org.ID)
	rec = e.do(http.MethodPost, "/api/auth/organization/set-active-team", map[string]any{"teamId": team.ID}, member)
	e.expect(rec, http.StatusOK, "")
	var activeTeam orgdtos.TeamResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &activeTeam))
	require.Equal(t, team.ID, activeTeam.ID)
	rec = e.do(http.MethodPost, "/api/auth/organization/set-active-team", map[string]any{}, member)
	e.expect(rec, http.StatusOK, "")
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &activeTeam))
	require.Equal(t, team.ID, activeTeam.ID, "an omitted teamId returns the active team")
	e.expect(e.do(http.MethodPost, "/api/auth/organization/set-active-team", map[string]any{"teamId": team.ID}, owner), http.StatusForbidden, "USER_IS_NOT_A_MEMBER_OF_THE_TEAM")
	e.expect(e.do(http.MethodPost, "/api/auth/organization/set-active-team", map[string]any{"teamId": "missing"}, owner), http.StatusBadRequest, "TEAM_NOT_FOUND")

	// Step 6: remove-team-member / remove-team return better-auth's messages
	rec = e.do(http.MethodPost, "/api/auth/organization/remove-team-member", add, owner)
	e.expect(rec, http.StatusOK, "")
	require.JSONEq(t, `{"message":"Team member removed successfully."}`, rec.Body.String())
	e.expect(e.do(http.MethodPost, "/api/auth/organization/remove-team-member", add, owner), http.StatusBadRequest, "USER_IS_NOT_A_MEMBER_OF_THE_TEAM")
	rec = e.do(http.MethodPost, "/api/auth/organization/set-active-team", map[string]any{"teamId": nil}, member)
	e.expect(rec, http.StatusOK, "")
	require.Equal(t, "null", string(bytesTrim(rec.Body.Bytes())))
	rec = e.do(http.MethodPost, "/api/auth/organization/remove-team", map[string]any{"teamId": team.ID, "organizationId": org.ID}, owner)
	e.expect(rec, http.StatusOK, "")
	require.JSONEq(t, `{"message":"Team removed successfully."}`, rec.Body.String())
}

// bytesTrim drops surrounding whitespace (Huma ends JSON bodies with a newline).
func bytesTrim(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}

// mustField returns the raw JSON of key in a JSON object.
func mustField(t *testing.T, body []byte, key string) json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &m))
	v, ok := m[key]
	require.True(t, ok, "missing key %q in %s", key, body)
	return v
}
