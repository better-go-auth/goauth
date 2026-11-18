package org_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	serv_interfaces "github.com/better-go-auth/goauth/src/app/services/interfaces"
	coremodels "github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/enums"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	orgdtos "github.com/better-go-auth/goauth/src/plugins/org/dtos"
	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
	gormorg "github.com/better-go-auth/goauth/src/plugins/org/repository/gorm"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func doOrgHTTP(t *testing.T, mux http.Handler, method, path string, body any, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// TestOrgHandlers_ConfigLimitsAndRestrictions tests org creation, deletion, membership, and invitation limits via HTTP handlers.
func TestOrgHandlers_ConfigLimitsAndRestrictions(t *testing.T) {
	// Step 1: Test AllowUserToCreateOrganization = false via HTTP handler
	allowFalse := false
	envDenied, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		AllowUserToCreateOrganization: &allowFalse,
	})
	_, deniedAuth := setupOrgHTTPUser(t, envDenied, "http-denied@example.com", "", "")
	rec := doOrgHTTP(t, envDenied.Mux, http.MethodPost, "/api/auth/organization/create", map[string]any{
		"name": "Denied Org",
		"slug": "denied-org",
	}, deniedAuth["Authorization"])
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION")

	// Step 2: Test OrganizationLimit = 1 and DisableOrganizationDeletion = true via HTTP handlers
	orgLimit := 1
	memLimit := 2
	invLimit := 1
	reinviteFalse := false
	env, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		OrganizationLimit:                  &orgLimit,
		DisableOrganizationDeletion:        true,
		MembershipLimit:                    &memLimit,
		InvitationLimit:                    &invLimit,
		CancelPendingInvitationsOnReInvite: &reinviteFalse,
	})
	ownerID, ownerAuth := setupOrgHTTPUser(t, env, "http-limit-owner@example.com", "", "")
	_ = ownerID

	// Create 1st org succeeds
	rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/create", map[string]any{
		"name": "HTTP Limit Org",
		"slug": "http-limit-org",
	}, ownerAuth["Authorization"])
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var orgResp orgdtos.OrgResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &orgResp))

	// Check slug availability via /organization/check-slug
	rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/check-slug", map[string]any{
		"slug": "http-limit-org",
	}, ownerAuth["Authorization"])
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())

	rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/check-slug", map[string]any{
		"slug": "available-slug-123",
	}, ownerAuth["Authorization"])
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// Create 2nd org fails with ORGANIZATION_LIMIT_REACHED
	rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/create", map[string]any{
		"name": "HTTP Limit Org 2",
		"slug": "http-limit-org-2",
	}, ownerAuth["Authorization"])
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS")

	// Update org using Better Auth nested `data` payload
	rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/update", map[string]any{
		"organizationId": orgResp.ID,
		"data": map[string]any{
			"name": "HTTP Limit Org Renamed",
		},
	}, ownerAuth["Authorization"])
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var updatedOrg orgdtos.OrgResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updatedOrg))
	require.Equal(t, "HTTP Limit Org Renamed", updatedOrg.Name)

	// Delete org fails with ORGANIZATION_DELETION_DISABLED on both POST and DELETE
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		rec = doOrgHTTP(t, env.Mux, method, "/api/auth/organization/delete", map[string]any{
			"organizationId": orgResp.ID,
		}, ownerAuth["Authorization"])
		require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
		require.Contains(t, rec.Body.String(), "ORGANIZATION_DELETION_DISABLED")
	}

	// Step 3: Invite 1st member succeeds
	rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/invite-member", map[string]any{
		"organizationId": orgResp.ID,
		"email":          "http-invitee1@example.com",
		"role":           "member",
	}, ownerAuth["Authorization"])
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// Invite 2nd member fails with INVITATION_LIMIT_REACHED (limit=1)
	rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/invite-member", map[string]any{
		"organizationId": orgResp.ID,
		"email":          "http-invitee2@example.com",
		"role":           "member",
	}, ownerAuth["Authorization"])
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "INVITATION_LIMIT_REACHED")
}

// TestOrgHandlers_EmailVerificationAndReInvite tests RequireEmailVerificationOnInvitation and CancelPendingInvitationsOnReInvite via HTTP.
func TestOrgHandlers_EmailVerificationAndReInvite(t *testing.T) {
	// Step 1: Configure RequireEmailVerificationOnInvitation=true and CancelPendingInvitationsOnReInvite=true
	reinviteTrue := true
	var sentEmail bool
	env, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		RequireEmailVerificationOnInvitation: true,
		CancelPendingInvitationsOnReInvite:   &reinviteTrue,
		InvitaionConfig: orgconfig.InvitaionConfig{
			InvitationExpiresIn: 2 * time.Hour,
			SendInvitationEmail: func(ctx context.Context, input orgconfig.SendInvitationInput) error {
				sentEmail = true
				return nil
			},
		},
	})
	_, ownerAuth := setupOrgHTTPUser(t, env, "http-verif-owner@example.com", "", "")
	inviteeID, inviteeAuth := setupOrgHTTPUser(t, env, "http-verif-invitee@example.com", "", "")

	// Mark invitee unverified
	require.NoError(t, env.DB.Model(&coremodels.User{}).Where("id = ?", inviteeID).Update("email_verified", false).Error)

	// Step 2: Create org and invite member twice (2nd cancels 1st)
	rec := doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/create", map[string]any{
		"name": "Verif HTTP Org",
		"slug": "verif-http-org",
	}, ownerAuth["Authorization"])
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var orgResp orgdtos.OrgResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &orgResp))

	rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/invite-member", map[string]any{
		"organizationId": orgResp.ID,
		"email":          "http-verif-invitee@example.com",
		"role":           "member",
	}, ownerAuth["Authorization"])
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.True(t, sentEmail)

	rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/invite-member", map[string]any{
		"organizationId": orgResp.ID,
		"email":          "http-verif-invitee@example.com",
		"role":           "admin",
	}, ownerAuth["Authorization"])
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var inv2 orgdtos.InvitationResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &inv2))

	// Step 3: Unverified recipient cannot get, reject, or accept invitation via HTTP handlers
	rec = doOrgHTTP(t, env.Mux, http.MethodGet, "/api/auth/organization/get-invitation?id="+inv2.ID, nil, inviteeAuth["Authorization"])
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION")

	rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/accept-invitation", map[string]any{
		"invitationId": inv2.ID,
	}, inviteeAuth["Authorization"])
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION")

	// Step 4: Verify recipient email and accept invitation via HTTP handler
	require.NoError(t, env.DB.Model(&coremodels.User{}).Where("id = ?", inviteeID).Update("email_verified", true).Error)

	rec = doOrgHTTP(t, env.Mux, http.MethodGet, "/api/auth/organization/get-invitation?id="+inv2.ID, nil, inviteeAuth["Authorization"])
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/accept-invitation", map[string]any{
		"invitationId": inv2.ID,
	}, inviteeAuth["Authorization"])
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// Step 5: Remove member by email via Better Auth `memberIdOrEmail` field
	rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/remove-member", map[string]any{
		"organizationId":  orgResp.ID,
		"memberIdOrEmail": "http-verif-invitee@example.com",
	}, ownerAuth["Authorization"])
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

// TestOrgHandlers_TeamsAndHooks tests Better Auth canonical team routes, dynamic team limits, custom default team, and hooks via HTTP.
func TestOrgHandlers_TeamsAndHooks(t *testing.T) {
	db := helpers.SetupTestDB(t, helpers.DBTypeSQLite)
	enabled := true
	hookEvents := make([]string, 0)

	env, _ := setupTeamsEnvWithDB(t, db, orgconfig.OrgConfig{
		Teams: &orgconfig.TeamsConfig{
			Enabled: true,
			DefaultTeam: &orgconfig.DefaultTeamConfig{
				Enabled: &enabled,
				CustomCreateDefaultTeam: func(ctx context.Context, org *orgmodels.Organization) (*orgmodels.Team, error) {
					now := coremodels.TimeNow()
					return gormorg.NewTeamRepo(db).CreateTeam(ctx, &orgmodels.Team{
						Base:           coremodels.Base{ID: coremodels.NewID(), CreatedAt: now, UpdatedAt: now},
						Name:           "Default-" + org.Name,
						OrganizationID: org.ID,
					})
				},
			},
			MaximumTeamsFn: func(ctx context.Context, data orgconfig.TeamLimitData) (int, error) {
				return 2, nil
			},
			MaximumMembersPerTeamFn: func(ctx context.Context, data orgconfig.TeamMemberLimitData) (int, error) {
				return 1, nil
			},
			AllowRemovingAllTeams: false,
		},
		OrganizationHooks: orgconfig.OrganizationHooks{
			BeforeCreateOrganization: func(ctx context.Context, data orgconfig.BeforeCreateOrgData) (*orgdtos.CreateOrgInput, error) {
				hookEvents = append(hookEvents, "beforeCreateOrg")
				return nil, nil
			},
			AfterCreateOrganization: func(ctx context.Context, data orgconfig.AfterCreateOrgData) error {
				hookEvents = append(hookEvents, "afterCreateOrg")
				return nil
			},
			BeforeCreateTeam: func(ctx context.Context, data orgconfig.BeforeCreateTeamData) (*orgdtos.CreateTeamInput, error) {
				hookEvents = append(hookEvents, "beforeCreateTeam")
				return nil, nil
			},
			AfterCreateTeam: func(ctx context.Context, data orgconfig.AfterCreateTeamData) error {
				hookEvents = append(hookEvents, "afterCreateTeam")
				return nil
			},
			BeforeUpdateTeam: func(ctx context.Context, data orgconfig.BeforeUpdateTeamData) (*orgdtos.UpdateTeamInput, error) {
				hookEvents = append(hookEvents, "beforeUpdateTeam")
				return nil, nil
			},
			AfterUpdateTeam: func(ctx context.Context, data orgconfig.AfterUpdateTeamData) error {
				hookEvents = append(hookEvents, "afterUpdateTeam")
				return nil
			},
			BeforeAddTeamMember: func(ctx context.Context, data orgconfig.BeforeAddTeamMemberData) (*orgdtos.AddTeamMemberInput, error) {
				hookEvents = append(hookEvents, "beforeAddTeamMember")
				return nil, nil
			},
			AfterAddTeamMember: func(ctx context.Context, data orgconfig.AfterAddTeamMemberData) error {
				hookEvents = append(hookEvents, "afterAddTeamMember")
				return nil
			},
			BeforeRemoveTeamMember: func(ctx context.Context, data orgconfig.BeforeRemoveTeamMemberData) error {
				hookEvents = append(hookEvents, "beforeRemoveTeamMember")
				return nil
			},
			AfterRemoveTeamMember: func(ctx context.Context, data orgconfig.AfterRemoveTeamMemberData) error {
				hookEvents = append(hookEvents, "afterRemoveTeamMember")
				return nil
			},
			BeforeDeleteTeam: func(ctx context.Context, data orgconfig.BeforeDeleteTeamData) error {
				hookEvents = append(hookEvents, "beforeDeleteTeam")
				return nil
			},
			AfterDeleteTeam: func(ctx context.Context, data orgconfig.AfterDeleteTeamData) error {
				hookEvents = append(hookEvents, "afterDeleteTeam")
				return nil
			},
		},
	})

	ownerID, ownerAuth := setupOrgHTTPUser(t, env, "http-teams-owner@example.com", "", "")
	memberID, memberAuth := setupOrgHTTPUser(t, env, "http-teams-member@example.com", "", "")
	_ = ownerID

	// Step 1: Create org -> creates custom default team and activates org on session
	rec := doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/create", map[string]any{
		"name": "TeamsHTTP",
		"slug": "teams-http",
	}, ownerAuth["Authorization"])
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var orgResp orgdtos.OrgResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &orgResp))

	// Step 2: List teams using Better Auth canonical route GET /organization/list-teams
	rec = doOrgHTTP(t, env.Mux, http.MethodGet, "/api/auth/organization/list-teams?organizationId="+orgResp.ID, nil, ownerAuth["Authorization"])
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var teams []orgdtos.TeamResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &teams))
	require.Len(t, teams, 1)
	require.Equal(t, "Default-TeamsHTTP", teams[0].Name)

	// Step 3: Create 2nd team via Better Auth canonical route POST /organization/create-team
	rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/create-team", map[string]any{
		"organizationId": orgResp.ID,
		"name":           "Backend",
	}, ownerAuth["Authorization"])
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var team2 orgdtos.TeamResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &team2))

	// 3rd team fails because MaximumTeamsFn = 2
	rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/create-team", map[string]any{
		"organizationId": orgResp.ID,
		"name":           "Frontend",
	}, ownerAuth["Authorization"])
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS")

	// Step 4: Update 2nd team via Better Auth nested `data` payload
	rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/update-team", map[string]any{
		"organizationId": orgResp.ID,
		"teamId":         team2.ID,
		"data":           map[string]any{"name": "Platform"},
	}, ownerAuth["Authorization"])
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// Step 5: Invite and accept member, then test team membership limit = 1
	rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/invite-member", map[string]any{
		"organizationId": orgResp.ID,
		"email":          "http-teams-member@example.com",
		"role":           "member",
	}, ownerAuth["Authorization"])
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var inv orgdtos.InvitationResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &inv))

	rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/accept-invitation", map[string]any{
		"invitationId": inv.ID,
	}, memberAuth["Authorization"])
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// Add 1st member to team2 succeeds
	rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/add-team-member", map[string]any{
		"organizationId": orgResp.ID,
		"teamId":         team2.ID,
		"userId":         memberID,
	}, ownerAuth["Authorization"])
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// Adding 2nd member (owner) to team2 fails with MAXIMUM_TEAM_MEMBERS_REACHED
	rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/add-team-member", map[string]any{
		"organizationId": orgResp.ID,
		"teamId":         team2.ID,
		"userId":         ownerID,
	}, ownerAuth["Authorization"])
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "TEAM_MEMBER_LIMIT_REACHED")

	// Remove team member and remove team2 via Better Auth canonical routes
	rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/remove-team-member", map[string]any{
		"organizationId": orgResp.ID,
		"teamId":         team2.ID,
		"userId":         memberID,
	}, ownerAuth["Authorization"])
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/remove-team", map[string]any{
		"organizationId": orgResp.ID,
		"teamId":         team2.ID,
	}, ownerAuth["Authorization"])
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// Deleting last remaining team fails because AllowRemovingAllTeams=false
	rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/remove-team", map[string]any{
		"organizationId": orgResp.ID,
		"teamId":         teams[0].ID,
	}, ownerAuth["Authorization"])
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "UNABLE_TO_REMOVE_LAST_TEAM")

	// Step 6: Verify all expected hook events fired
	joined := strings.Join(hookEvents, ",")
	for _, ev := range []string{
		"beforeCreateOrg", "afterCreateOrg",
		"beforeCreateTeam", "afterCreateTeam",
		"beforeUpdateTeam", "afterUpdateTeam",
		"beforeAddTeamMember", "afterAddTeamMember",
		"beforeRemoveTeamMember", "afterRemoveTeamMember",
		"beforeDeleteTeam", "afterDeleteTeam",
	} {
		require.Contains(t, joined, ev)
	}
}

func setupSystemAdminUser(t *testing.T, env *helpers.TestEnv, email string) (string, string) {
	t.Helper()
	user := &coremodels.User{
		UserDto: coremodels.UserDto{
			FirstName:     "Platform",
			LastName:      "Admin",
			Email:         email,
			EmailVerified: true,
			Role:          enums.Admin,
		},
	}
	require.NoError(t, env.DB.Create(user).Error)
	swu, err := env.Auth.Sessions().Create(context.Background(), user, serv_interfaces.SessionMeta{}, serv_interfaces.SessionCreateOptions{})
	require.NoError(t, err)
	return user.ID, helpers.SignedBearerAuth(swu.Session.Token, env.Options.Secret)
}

// TestOrgHandlers_Issues2To6 tests Issues 2–6 across SQLite, PostgreSQL, and MySQL.
func TestOrgHandlers_Issues2To6(t *testing.T) {
	helpers.RunForEachDB(t, func(t *testing.T, db *gorm.DB, dbType helpers.DatabaseType) {
		env, orgPlugin := setupTeamsEnvWithDB(t, db, orgconfig.OrgConfig{
			OrgNeedsApproval: true,
			Teams: &orgconfig.TeamsConfig{
				Enabled: true,
			},
		})

		adminID, adminAuth := setupSystemAdminUser(t, env, "sysadmin-issues@example.com")
		ownerID, ownerAuth := setupOrgHTTPUser(t, env, "owner-issues@example.com", "", "")
		memberID, memberAuth := setupOrgHTTPUser(t, env, "member-issues@example.com", "", "")
		_ = memberID
		coOwnerID, coOwnerAuth := setupOrgHTTPUser(t, env, "coowner-issues@example.com", "", "")

		// Step 1 (Better Auth parity): /organization/create behaves uniformly (pending when OrgNeedsApproval=true) even for system Admin; /admin/organization/create activates immediately
		rec := doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/create", map[string]any{
			"name": "Needs Approval Alpha",
			"slug": "needs-approval-alpha",
		}, ownerAuth["Authorization"])
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var pendingOrg orgdtos.OrgResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &pendingOrg))
		require.Equal(t, string(orgmodels.OrgStatusPending), pendingOrg.Status)

		rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/create", map[string]any{
			"name": "Admin Regular Endpoint Pending Org",
			"slug": "admin-regular-endpoint-pending",
		}, adminAuth)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var adminRegularOrg orgdtos.OrgResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &adminRegularOrg))
		require.Equal(t, string(orgmodels.OrgStatusPending), adminRegularOrg.Status)

		// Step 2 (Issue 6): POST /admin/organization/create (non-admin forbidden, admin creates active org with custom ownerUserId)
		rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/admin/organization/create", map[string]any{
			"name": "Denied Admin Create",
			"slug": "denied-admin-create",
		}, ownerAuth["Authorization"])
		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())

		rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/admin/organization/create", map[string]any{
			"name":        "Acme Platform Labs",
			"slug":        "acme-platform-labs",
			"ownerUserId": ownerID,
		}, adminAuth)
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
		var orgResp orgdtos.OrgResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &orgResp))
		require.Equal(t, string(orgmodels.OrgStatusActive), orgResp.Status)

		// Step 3 (Issue 6): GET /admin/organization/get & GET /admin/organization/list?q=...&_q=...
		rec = doOrgHTTP(t, env.Mux, http.MethodGet, "/api/auth/admin/organization/get?organizationId="+orgResp.ID, nil, ownerAuth["Authorization"])
		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())

		rec = doOrgHTTP(t, env.Mux, http.MethodGet, "/api/auth/admin/organization/get?organizationId="+orgResp.ID, nil, adminAuth)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var fetchedOrg orgdtos.OrgResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &fetchedOrg))
		require.Equal(t, orgResp.ID, fetchedOrg.ID)

		rec = doOrgHTTP(t, env.Mux, http.MethodGet, "/api/auth/admin/organization/list?q=PLaTfOrM", nil, adminAuth)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var searchResp struct {
			Organizations []orgdtos.OrgResponse `json:"organizations"`
			Total         int64                 `json:"total"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &searchResp))
		require.Equal(t, int64(1), searchResp.Total)
		require.Equal(t, orgResp.ID, searchResp.Organizations[0].ID)

		rec = doOrgHTTP(t, env.Mux, http.MethodGet, "/api/auth/admin/organization/list?_q=NEEDS-APPROVAL-ALPHA", nil, adminAuth)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &searchResp))
		require.Equal(t, int64(1), searchResp.Total)
		require.Equal(t, pendingOrg.ID, searchResp.Organizations[0].ID)

		// Step 4 (Issue 4): Invite members & inspect enriched GET /organization/list-user-invitations
		rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/invite-member", map[string]any{
			"organizationId": orgResp.ID,
			"email":          "member-issues@example.com",
			"role":           "member",
		}, ownerAuth["Authorization"])
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var invMember orgdtos.InvitationResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &invMember))

		rec = doOrgHTTP(t, env.Mux, http.MethodGet, "/api/auth/organization/list-user-invitations", nil, memberAuth["Authorization"])
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		// better-auth returns an array (goauth adds organizationSlug and inviter to organizationName)
		var inboxResp []orgdtos.InvitationResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &inboxResp))
		require.Len(t, inboxResp, 1)
		require.Equal(t, invMember.ID, inboxResp[0].ID)
		require.NotNil(t, inboxResp[0].OrganizationName)
		require.Equal(t, "Acme Platform Labs", *inboxResp[0].OrganizationName)
		require.NotNil(t, inboxResp[0].OrganizationSlug)
		require.Equal(t, "acme-platform-labs", *inboxResp[0].OrganizationSlug)
		require.NotNil(t, inboxResp[0].Inviter)
		require.Equal(t, "owner-issues@example.com", inboxResp[0].Inviter.Email)

		// Invite & accept co-owner too, and member accepts
		rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/accept-invitation", map[string]any{
			"invitationId": invMember.ID,
		}, memberAuth["Authorization"])
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/invite-member", map[string]any{
			"organizationId": orgResp.ID,
			"email":          "coowner-issues@example.com",
			"role":           "owner",
		}, ownerAuth["Authorization"])
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var invCoOwner orgdtos.InvitationResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &invCoOwner))

		// Step 5 (Issue 5): Regular "member" can call list-members (not 403)
		rec = doOrgHTTP(t, env.Mux, http.MethodGet, "/api/auth/organization/list-members?organizationId="+orgResp.ID, nil, memberAuth["Authorization"])
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var listMembersResp struct {
			Members []orgdtos.MemberResponse `json:"members"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &listMembersResp))
		require.Len(t, listMembersResp.Members, 2)

		// Step 6 (Issue 5): Sole owner blocked from leaving, regular member sets active org then leaves cleanly
		rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/leave", map[string]any{
			"organizationId": orgResp.ID,
		}, ownerAuth["Authorization"])
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		require.Contains(t, rec.Body.String(), "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER")

		rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/set-active", map[string]any{
			"organizationId": orgResp.ID,
		}, memberAuth["Authorization"])
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/leave", map[string]any{
			"organizationId": orgResp.ID,
		}, memberAuth["Authorization"])
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		// Verify member's activeOrganizationId was cleared on session and org is gone from member's list
		rec = doOrgHTTP(t, env.Mux, http.MethodGet, "/api/auth/get-session", nil, memberAuth["Authorization"])
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var sessResp struct {
			Session struct {
				ActiveOrganizationID *string `json:"activeOrganizationId"`
			} `json:"session"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &sessResp))
		require.Nil(t, sessResp.Session.ActiveOrganizationID)

		// Co-owner accepts; now original owner can leave successfully because co-owner remains
		rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/accept-invitation", map[string]any{
			"invitationId": invCoOwner.ID,
		}, coOwnerAuth["Authorization"])
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		// Step 7 (Issues 2 & 3): Create team, add member, verify ListTeamMembers (preloaded User) & system Admin access to ListTeams/GetTeam/ListTeamMembers
		rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/team/create", map[string]any{
			"organizationId": orgResp.ID,
			"name":           "Backend",
		}, coOwnerAuth["Authorization"])
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var teamResp orgdtos.TeamResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &teamResp))

		rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/team/add-member", map[string]any{
			"organizationId": orgResp.ID,
			"teamId":         teamResp.ID,
			"userId":         coOwnerID,
		}, coOwnerAuth["Authorization"])
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		// Non-members (even system Admin) receive 403 Forbidden on /organization/* endpoints (100% Better Auth parity)
		rec = doOrgHTTP(t, env.Mux, http.MethodGet, "/api/auth/organization/list-members?organizationId="+orgResp.ID, nil, adminAuth)
		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())

		rec = doOrgHTTP(t, env.Mux, http.MethodGet, "/api/auth/organization/team/list?organizationId="+orgResp.ID, nil, adminAuth)
		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())

		_, err := orgPlugin.Service().GetTeam(context.Background(), teamResp.ID, adminID)
		require.Error(t, err)

		for _, endpoint := range []string{
			"/api/auth/organization/team/list-members?teamId=" + teamResp.ID,
			"/api/auth/organization/list-team-members?teamId=" + teamResp.ID,
		} {
			// better-auth's list-team-members answers 400 USER_IS_NOT_A_MEMBER_OF_THE_TEAM to non-members
			rec = doOrgHTTP(t, env.Mux, http.MethodGet, endpoint, nil, adminAuth)
			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			require.Contains(t, rec.Body.String(), "USER_IS_NOT_A_MEMBER_OF_THE_TEAM")
		}

		// Org members can ListTeams, GetTeam, and ListTeamMembers (both /team/list-members and /list-team-members) with preloaded User
		rec = doOrgHTTP(t, env.Mux, http.MethodGet, "/api/auth/organization/team/list?organizationId="+orgResp.ID, nil, coOwnerAuth["Authorization"])
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var teamsResp []orgdtos.TeamResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &teamsResp))
		// Includes default team created by AdminCreateOrganization + manually created "Backend" team
		require.Len(t, teamsResp, 2)

		gotTeam, err := orgPlugin.Service().GetTeam(context.Background(), teamResp.ID, coOwnerID)
		require.NoError(t, err)
		require.Equal(t, teamResp.ID, gotTeam.ID)

		for _, endpoint := range []string{
			"/api/auth/organization/team/list-members?teamId=" + teamResp.ID,
			"/api/auth/organization/list-team-members?teamId=" + teamResp.ID,
		} {
			rec = doOrgHTTP(t, env.Mux, http.MethodGet, endpoint, nil, coOwnerAuth["Authorization"])
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			var tmResp []orgdtos.TeamMemberResponse
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &tmResp))
			require.Len(t, tmResp, 1)
			require.Equal(t, coOwnerID, tmResp[0].UserID)
			require.NotNil(t, tmResp[0].User)
			require.Equal(t, "coowner-issues@example.com", tmResp[0].User.Email)
		}

		// Original owner can now leave since coOwnerID is a second owner
		rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/organization/leave", map[string]any{
			"organizationId": orgResp.ID,
		}, ownerAuth["Authorization"])
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		// Step 8: AdminBlockOrg merges blockReason into existing JSON Metadata without overwriting it
		metaJSON := orgdtos.JSONString(`{"plan":"pro"}`)
		_, err = orgPlugin.Service().UpdateOrganization(context.Background(), orgResp.ID, orgdtos.UpdateOrgInput{Metadata: &metaJSON}, coOwnerID)
		require.NoError(t, err)
		rec = doOrgHTTP(t, env.Mux, http.MethodPost, "/api/auth/admin/organization/block", map[string]any{
			"organizationId": orgResp.ID,
			"reason":         "billing",
		}, adminAuth)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var blockedOrg orgdtos.OrgResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &blockedOrg))
		// metadata is returned as a JSON object, like better-auth
		require.NotNil(t, blockedOrg.Metadata)
		parsedMeta, ok := blockedOrg.Metadata.(map[string]any)
		require.True(t, ok, "metadata should be an object, got %T", blockedOrg.Metadata)
		require.Equal(t, "pro", parsedMeta["plan"])
		require.Equal(t, "billing", parsedMeta["blockReason"])
	})
}

// TestOrg_InvitationLimit_CountsPendingOnly verifies canceled/accepted invitations do not consume InvitationLimit.
func TestOrg_InvitationLimit_CountsPendingOnly(t *testing.T) {
	ctx := context.Background()
	invLimit := 1
	env, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		InvitationLimit: &invLimit,
	})
	ownerID, _ := setupOrgUser(t, env, "invlimit-owner@example.com", "", "")
	org, err := env.OrgService.CreateOrganization(ctx, ownerID, orgdtos.CreateOrgInput{
		Name: "Pending Limit Org",
		Slug: "pending-limit-org",
	})
	require.NoError(t, err)

	inv1, err := env.OrgService.InviteMember(ctx, ownerID, orgdtos.InviteMemberInput{
		OrganizationID: org.ID,
		Email:          "first-inv@example.com",
		Role:           orgmodels.OrgRoleMember,
	})
	require.NoError(t, err)
	require.NoError(t, env.OrgService.CancelInvitation(ctx, inv1.ID, ownerID))

	// After canceling the only pending invitation, inviting another user succeeds
	_, err = env.OrgService.InviteMember(ctx, ownerID, orgdtos.InviteMemberInput{
		OrganizationID: org.ID,
		Email:          "second-inv@example.com",
		Role:           orgmodels.OrgRoleMember,
	})
	require.NoError(t, err)
}
