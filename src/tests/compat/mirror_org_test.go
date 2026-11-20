package compattest

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/config"
	coremodels "github.com/better-go-auth/goauth/src/models"
	bearer "github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
	"github.com/better-go-auth/goauth/src/plugins/org"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	orgdtos "github.com/better-go-auth/goauth/src/plugins/org/dtos"
	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestGoMirror_Org mirrors src/tests/compat/client/test-org.mjs in pure Go.
func TestGoMirror_Org(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:gomirror_org_%d?mode=memory&cache=shared", time.Now().UnixNano())),
		&gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)

	var mu sync.Mutex
	hookEvents := make([]string, 0)
	recordHook := func(name string) {
		mu.Lock()
		hookEvents = append(hookEvents, name)
		mu.Unlock()
	}
	var invitationEmailsSent int32

	orgLimit, memLimit, invLimit, maxTeams, maxTeamMembers := 2, 3, 5, 2, 2
	reinviteTrue, defaultTeamEnabled := true, true

	orgPlugin, err := org.New(org.OrgOptions{Config: orgconfig.OrgConfig{
		OrganizationLimit:                    &orgLimit,
		MembershipLimit:                      &memLimit,
		InvitationLimit:                      &invLimit,
		CancelPendingInvitationsOnReInvite:   &reinviteTrue,
		RequireEmailVerificationOnInvitation: true,
		InvitaionConfig: orgconfig.InvitaionConfig{
			InvitationExpiresIn: 2 * time.Hour,
			SendInvitationEmail: func(ctx context.Context, input orgconfig.SendInvitationInput) error {
				atomic.AddInt32(&invitationEmailsSent, 1)
				return nil
			},
		},
		Teams: &orgconfig.TeamsConfig{
			Enabled: true,
			DefaultTeam: &orgconfig.DefaultTeamConfig{
				Enabled: &defaultTeamEnabled,
				CustomCreateDefaultTeam: func(ctx context.Context, o *orgmodels.Organization) (*orgmodels.Team, error) {
					now := coremodels.TimeNow()
					team := &orgmodels.Team{
						Base:           coremodels.Base{ID: coremodels.NewID(), CreatedAt: now, UpdatedAt: now},
						Name:           "Core-" + o.Name,
						OrganizationID: o.ID,
					}
					// the hook runs inside the plugin's transaction (ctx)
					return team, gormutil.GetDB(ctx, db).Create(team).Error
				},
			},
			MaximumTeams:          &maxTeams,
			MaximumMembersPerTeam: &maxTeamMembers,
			AllowRemovingAllTeams: false,
		},
		OrganizationHooks: orgconfig.OrganizationHooks{
			BeforeCreateOrganization: func(ctx context.Context, data orgconfig.BeforeCreateOrgData) (*orgdtos.CreateOrgInput, error) {
				recordHook("beforeCreateOrg")
				return nil, nil
			},
			AfterCreateOrganization: func(ctx context.Context, data orgconfig.AfterCreateOrgData) error {
				recordHook("afterCreateOrg")
				return nil
			},
			BeforeUpdateOrganization: func(ctx context.Context, data orgconfig.BeforeUpdateOrgData) (*orgdtos.UpdateOrgInput, error) {
				recordHook("beforeUpdateOrg")
				return nil, nil
			},
			AfterUpdateOrganization: func(ctx context.Context, data orgconfig.AfterUpdateOrgData) error {
				recordHook("afterUpdateOrg")
				return nil
			},
			BeforeDeleteOrganization: func(ctx context.Context, data orgconfig.BeforeDeleteOrgData) error {
				recordHook("beforeDeleteOrg")
				return nil
			},
			AfterDeleteOrganization: func(ctx context.Context, data orgconfig.AfterDeleteOrgData) error {
				recordHook("afterDeleteOrg")
				return nil
			},
			BeforeAddMember: func(ctx context.Context, data orgconfig.BeforeAddMemberData) (*orgmodels.Member, error) {
				recordHook("beforeAddMember")
				return nil, nil
			},
			AfterAddMember: func(ctx context.Context, data orgconfig.AfterAddMemberData) error {
				recordHook("afterAddMember")
				return nil
			},
			BeforeUpdateMemberRole: func(ctx context.Context, data orgconfig.BeforeUpdateMemberRoleData) (*string, error) {
				recordHook("beforeUpdateMemberRole")
				return nil, nil
			},
			AfterUpdateMemberRole: func(ctx context.Context, data orgconfig.AfterUpdateMemberRoleData) error {
				recordHook("afterUpdateMemberRole")
				return nil
			},
			BeforeRemoveMember: func(ctx context.Context, data orgconfig.BeforeRemoveMemberData) error {
				recordHook("beforeRemoveMember")
				return nil
			},
			AfterRemoveMember: func(ctx context.Context, data orgconfig.AfterRemoveMemberData) error {
				recordHook("afterRemoveMember")
				return nil
			},
			BeforeCreateInvitation: func(ctx context.Context, data orgconfig.BeforeCreateInvitationData) (*orgdtos.InviteMemberInput, error) {
				recordHook("beforeCreateInvitation")
				return nil, nil
			},
			AfterCreateInvitation: func(ctx context.Context, data orgconfig.AfterCreateInvitationData) error {
				recordHook("afterCreateInvitation")
				return nil
			},
			BeforeAcceptInvitation: func(ctx context.Context, data orgconfig.BeforeAcceptInvitationData) error {
				recordHook("beforeAcceptInvitation")
				return nil
			},
			AfterAcceptInvitation: func(ctx context.Context, data orgconfig.AfterAcceptInvitationData) error {
				recordHook("afterAcceptInvitation")
				return nil
			},
			BeforeCreateTeam: func(ctx context.Context, data orgconfig.BeforeCreateTeamData) (*orgdtos.CreateTeamInput, error) {
				recordHook("beforeCreateTeam")
				return nil, nil
			},
			AfterCreateTeam: func(ctx context.Context, data orgconfig.AfterCreateTeamData) error {
				recordHook("afterCreateTeam")
				return nil
			},
			BeforeUpdateTeam: func(ctx context.Context, data orgconfig.BeforeUpdateTeamData) (*orgdtos.UpdateTeamInput, error) {
				recordHook("beforeUpdateTeam")
				return nil, nil
			},
			AfterUpdateTeam: func(ctx context.Context, data orgconfig.AfterUpdateTeamData) error {
				recordHook("afterUpdateTeam")
				return nil
			},
			BeforeDeleteTeam: func(ctx context.Context, data orgconfig.BeforeDeleteTeamData) error {
				recordHook("beforeDeleteTeam")
				return nil
			},
			AfterDeleteTeam: func(ctx context.Context, data orgconfig.AfterDeleteTeamData) error {
				recordHook("afterDeleteTeam")
				return nil
			},
			BeforeAddTeamMember: func(ctx context.Context, data orgconfig.BeforeAddTeamMemberData) (*orgdtos.AddTeamMemberInput, error) {
				recordHook("beforeAddTeamMember")
				return nil, nil
			},
			AfterAddTeamMember: func(ctx context.Context, data orgconfig.AfterAddTeamMemberData) error {
				recordHook("afterAddTeamMember")
				return nil
			},
			BeforeRemoveTeamMember: func(ctx context.Context, data orgconfig.BeforeRemoveTeamMemberData) error {
				recordHook("beforeRemoveTeamMember")
				return nil
			},
			AfterRemoveTeamMember: func(ctx context.Context, data orgconfig.AfterRemoveTeamMemberData) error {
				recordHook("afterRemoveTeamMember")
				return nil
			},
		},
	}})
	require.NoError(t, err)

	s := NewServer(t,
		WithDB(db),
		WithPlugin(bearer.New(bearerconfig.DefaultConfig())),
		WithPlugin(orgPlugin),
		WithConfig(func(c *config.AuthConfig) {
			compatMode(c)
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	owner := newBearerTestClient(s.URL)
	invitee := newBearerTestClient(s.URL)
	ts := time.Now().UnixNano()
	ownerEmail := fmt.Sprintf("go-org-owner-%d@example.com", ts)
	inviteeEmail := fmt.Sprintf("go-org-invitee-%d@example.com", ts)
	password := "Password123!"

	// [1] Register owner and invitee
	res := owner.post(t, "/api/auth/sign-up/email", map[string]any{"email": ownerEmail, "password": password, "name": "Org Owner"})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	var ownerUp struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	res.JSON(t, &ownerUp)
	ownerUserID := ownerUp.User.ID
	res = invitee.post(t, "/api/auth/sign-up/email", map[string]any{"email": inviteeEmail, "password": password, "name": "Org Invitee"})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	var invUp struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	res.JSON(t, &invUp)
	inviteeUserID := invUp.User.ID

	// [2] Check slug & create organization
	slug := fmt.Sprintf("go-acme-%d", ts)
	res = owner.post(t, "/api/auth/organization/check-slug", map[string]any{"slug": slug})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))

	res = owner.post(t, "/api/auth/organization/create", map[string]any{"name": "Acme Corp", "slug": slug})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	var createdOrg orgdtos.CreatedOrgResponse
	res.JSON(t, &createdOrg)
	require.NotContains(t, string(res.Body), "$schema")
	require.Len(t, createdOrg.Members, 1, "create returns the creator's membership")
	require.Equal(t, "owner", createdOrg.Members[0].Role)

	res = owner.post(t, "/api/auth/organization/check-slug", map[string]any{"slug": slug})
	require.Equal(t, http.StatusBadRequest, res.Status, string(res.Body))
	require.Contains(t, string(res.Body), "ORGANIZATION_SLUG_ALREADY_TAKEN")

	// [3] get-full-organization, list, update, set-active
	res = owner.get(t, "/api/auth/organization/get-full-organization?organizationId="+createdOrg.ID)
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	var full orgdtos.FullOrgResponse
	res.JSON(t, &full)
	require.Equal(t, createdOrg.ID, full.ID)
	require.Len(t, full.Members, 1)
	require.NotNil(t, full.Members[0].User)
	require.Equal(t, ownerEmail, full.Members[0].User.Email)
	require.NotNil(t, full.Invitations)
	require.NotNil(t, full.Teams, "teams are included when the feature is enabled")
	require.Len(t, *full.Teams, 1)

	res = owner.get(t, "/api/auth/organization/list")
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	var listOrgs []orgdtos.OrgResponse
	res.JSON(t, &listOrgs)
	require.GreaterOrEqual(t, len(listOrgs), 1)

	res = owner.post(t, "/api/auth/organization/update", map[string]any{
		"organizationId": createdOrg.ID,
		"data":           map[string]any{"name": "Acme Updated"},
	})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))

	res = owner.post(t, "/api/auth/organization/set-active", map[string]any{"organizationSlug": slug})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))

	// [4] Teams: custom default team + create-team + MaximumTeams=2 + update-team
	res = owner.get(t, "/api/auth/organization/list-teams?organizationId="+createdOrg.ID)
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	var teams []orgdtos.TeamResponse
	res.JSON(t, &teams)
	require.Len(t, teams, 1)
	require.Equal(t, "Core-Acme Corp", teams[0].Name)

	res = owner.post(t, "/api/auth/organization/create-team", map[string]any{"name": "Engineering", "organizationId": createdOrg.ID})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	var team2 orgdtos.TeamResponse
	res.JSON(t, &team2)

	res = owner.post(t, "/api/auth/organization/create-team", map[string]any{"name": "TooMany", "organizationId": createdOrg.ID})
	require.NotEqual(t, http.StatusOK, res.Status)

	res = owner.post(t, "/api/auth/organization/update-team", map[string]any{"teamId": team2.ID, "data": map[string]any{"name": "Platform"}})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))

	// [5] Invitations: re-invite cancellation, verification gate, list-user-invitations, accept
	res = owner.post(t, "/api/auth/organization/invite-member", map[string]any{"email": inviteeEmail, "role": "member", "organizationId": createdOrg.ID})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	var inv1 orgdtos.InvitationResponse
	res.JSON(t, &inv1)

	res = owner.post(t, "/api/auth/organization/invite-member", map[string]any{"email": inviteeEmail, "role": "admin", "organizationId": createdOrg.ID})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	var inv2 orgdtos.InvitationResponse
	res.JSON(t, &inv2)
	require.NotEqual(t, inv1.ID, inv2.ID)

	res = invitee.get(t, "/api/auth/organization/get-invitation?id="+inv2.ID)
	require.Equal(t, http.StatusForbidden, res.Status)
	res = invitee.post(t, "/api/auth/organization/accept-invitation", map[string]any{"invitationId": inv2.ID})
	require.Equal(t, http.StatusForbidden, res.Status)

	// like verify-email: store the flag and refresh the user copy cached in the invitee's sessions
	verified, err := s.Auth.Repositories().UpdateUser(context.Background(), inviteeUserID, map[string]any{"emailVerified": true})
	require.NoError(t, err)
	s.Auth.Sessions().RefreshUser(context.Background(), verified)

	res = invitee.get(t, "/api/auth/organization/list-user-invitations")
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	var inbox []orgdtos.InvitationResponse
	res.JSON(t, &inbox)
	require.Len(t, inbox, 1)
	require.Equal(t, inv2.ID, inbox[0].ID)
	require.NotNil(t, inbox[0].OrganizationName)
	require.Equal(t, "Acme Updated", *inbox[0].OrganizationName)
	require.NotNil(t, inbox[0].Inviter)
	require.Equal(t, ownerEmail, inbox[0].Inviter.Email)

	res = invitee.get(t, "/api/auth/organization/get-invitation?id="+inv2.ID)
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	var details orgdtos.InvitationDetailsResponse
	res.JSON(t, &details)
	require.Equal(t, ownerEmail, details.InviterEmail)
	require.NotNil(t, details.OrganizationSlug)
	require.Equal(t, slug, *details.OrganizationSlug)

	// the invitee has no active organization yet
	res = invitee.get(t, "/api/auth/organization/get-active-member")
	require.Equal(t, http.StatusBadRequest, res.Status, string(res.Body))
	require.Contains(t, string(res.Body), "NO_ACTIVE_ORGANIZATION")

	res = invitee.post(t, "/api/auth/organization/accept-invitation", map[string]any{"invitationId": inv2.ID})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	var accepted orgdtos.InvitationResultResponse
	res.JSON(t, &accepted)
	require.NotNil(t, accepted.Invitation)
	require.Equal(t, "accepted", accepted.Invitation.Status)
	require.NotNil(t, accepted.Member)
	require.Equal(t, "admin", accepted.Member.Role)

	// accepting made the organization active: get-active-member / get-active-member-role work without a query
	res = invitee.get(t, "/api/auth/organization/get-active-member")
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	var activeMember orgdtos.MemberResponse
	res.JSON(t, &activeMember)
	require.Equal(t, inviteeUserID, activeMember.UserID)
	require.Equal(t, createdOrg.ID, activeMember.OrganizationID)
	require.NotNil(t, activeMember.User)
	require.Equal(t, inviteeEmail, activeMember.User.Email)

	res = invitee.get(t, "/api/auth/organization/get-active-member-role")
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	require.JSONEq(t, `{"role":"admin"}`, string(res.Body))
	res = invitee.get(t, "/api/auth/organization/get-active-member-role?organizationSlug="+slug+"&userId="+ownerUserID)
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	require.JSONEq(t, `{"role":"owner"}`, string(res.Body))

	// [6] Members & Team Members
	res = owner.get(t, "/api/auth/organization/list-members?organizationId="+createdOrg.ID)
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	var memResp struct {
		Members []orgdtos.MemberResponse `json:"members"`
	}
	res.JSON(t, &memResp)
	require.Len(t, memResp.Members, 2)
	var inviteeMemberID string
	for _, m := range memResp.Members {
		if m.UserID == inviteeUserID {
			inviteeMemberID = m.ID
		}
	}
	require.NotEmpty(t, inviteeMemberID)

	res = owner.post(t, "/api/auth/organization/add-team-member", map[string]any{"teamId": team2.ID, "userId": inviteeUserID, "organizationId": createdOrg.ID})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))

	// like better-auth, only members of the team may list its members
	res = owner.get(t, "/api/auth/organization/list-team-members?teamId="+team2.ID)
	require.Equal(t, http.StatusBadRequest, res.Status, string(res.Body))
	require.Contains(t, string(res.Body), "USER_IS_NOT_A_MEMBER_OF_THE_TEAM")
	res = invitee.get(t, "/api/auth/organization/list-team-members?teamId="+team2.ID)
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	var tmList []orgdtos.TeamMemberResponse
	res.JSON(t, &tmList)
	require.Len(t, tmList, 1)
	require.NotNil(t, tmList[0].User)
	require.Equal(t, inviteeEmail, tmList[0].User.Email)

	// list-user-teams: the invitee is only in team2
	res = invitee.get(t, "/api/auth/organization/list-user-teams")
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	var userTeams []orgdtos.TeamResponse
	res.JSON(t, &userTeams)
	require.Len(t, userTeams, 1)
	require.Equal(t, team2.ID, userTeams[0].ID)

	res = invitee.post(t, "/api/auth/organization/set-active-team", map[string]any{"teamId": team2.ID})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	var activeTeam orgdtos.TeamResponse
	res.JSON(t, &activeTeam)
	require.Equal(t, team2.ID, activeTeam.ID, "set-active-team returns the team")
	res = owner.post(t, "/api/auth/organization/remove-team-member", map[string]any{"teamId": team2.ID, "userId": inviteeUserID, "organizationId": createdOrg.ID})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	require.JSONEq(t, `{"message":"Team member removed successfully."}`, string(res.Body))
	res = owner.post(t, "/api/auth/organization/remove-team", map[string]any{"teamId": team2.ID, "organizationId": createdOrg.ID})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	require.JSONEq(t, `{"message":"Team removed successfully."}`, string(res.Body))

	res = owner.post(t, "/api/auth/organization/update-member-role", map[string]any{"memberId": inviteeMemberID, "role": "member", "organizationId": createdOrg.ID})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	res = invitee.get(t, "/api/auth/organization/get-active-member-role")
	require.JSONEq(t, `{"role":"member"}`, string(res.Body))

	res = invitee.get(t, "/api/auth/organization/list-members?organizationId="+createdOrg.ID)
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))

	res = owner.post(t, "/api/auth/organization/leave", map[string]any{"organizationId": createdOrg.ID})
	require.Equal(t, http.StatusBadRequest, res.Status, string(res.Body))
	require.Contains(t, string(res.Body), "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER")

	res = owner.post(t, "/api/auth/organization/remove-member", map[string]any{"memberIdOrEmail": inviteeEmail, "organizationId": createdOrg.ID})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))

	// [7] OrganizationLimit=2 + leave
	res = owner.post(t, "/api/auth/organization/create", map[string]any{"name": "Second Org", "slug": fmt.Sprintf("go-second-%d", ts)})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	var org2 orgdtos.OrgResponse
	res.JSON(t, &org2)

	res = owner.post(t, "/api/auth/organization/invite-member", map[string]any{"email": inviteeEmail, "role": "member", "organizationId": org2.ID})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	var invOrg2 orgdtos.InvitationResponse
	res.JSON(t, &invOrg2)
	res = invitee.post(t, "/api/auth/organization/accept-invitation", map[string]any{"invitationId": invOrg2.ID})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	res = invitee.post(t, "/api/auth/organization/leave", map[string]any{"organizationId": org2.ID})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))

	res = owner.post(t, "/api/auth/organization/create", map[string]any{"name": "Third Org", "slug": fmt.Sprintf("go-third-%d", ts)})
	require.Equal(t, http.StatusForbidden, res.Status, string(res.Body))
	require.Contains(t, string(res.Body), "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS")

	// [8] Delete organization
	res = owner.post(t, "/api/auth/organization/delete", map[string]any{"organizationId": createdOrg.ID})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))

	// [9] Restricted server checks (AllowUserToCreateOrganizationFn + DisableOrganizationDeletion)
	rdb, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:gomirror_org_res_%d?mode=memory&cache=shared", time.Now().UnixNano())),
		&gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	rOrgPlugin, err := org.New(org.OrgOptions{Config: orgconfig.OrgConfig{
		AllowUserToCreateOrganizationFn: func(ctx context.Context, user *coremodels.User) (bool, error) {
			return user != nil && user.Email == "restricted-owner@example.com", nil
		},
		DisableOrganizationDeletion: true,
	}})
	require.NoError(t, err)
	rs := NewServer(t,
		WithDB(rdb),
		WithPlugin(bearer.New(bearerconfig.DefaultConfig())),
		WithPlugin(rOrgPlugin),
		WithConfig(func(c *config.AuthConfig) {
			compatMode(c)
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	rOwner := newBearerTestClient(rs.URL)
	rOther := newBearerTestClient(rs.URL)
	res = rOwner.post(t, "/api/auth/sign-up/email", map[string]any{"email": "restricted-owner@example.com", "password": password, "name": "R Owner"})
	require.Equal(t, http.StatusOK, res.Status)
	var rOwnerUp struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	res.JSON(t, &rOwnerUp)
	seededOrg, err := rOrgPlugin.Service().CreateOrganization(context.Background(), rOwnerUp.User.ID, orgdtos.CreateOrgInput{
		Name: "Locked Org",
		Slug: "locked-org",
	})
	require.NoError(t, err)

	res = rOther.post(t, "/api/auth/sign-up/email", map[string]any{"email": fmt.Sprintf("restricted-%d@example.com", ts), "password": password, "name": "R Other"})
	require.Equal(t, http.StatusOK, res.Status)
	res = rOther.post(t, "/api/auth/organization/create", map[string]any{"name": "Blocked", "slug": "blocked-go"})
	require.Equal(t, http.StatusForbidden, res.Status)

	res = rOwner.post(t, "/api/auth/organization/delete", map[string]any{"organizationId": seededOrg.ID})
	require.NotEqual(t, http.StatusOK, res.Status)

	// Verify server hooks & invitation emails
	require.GreaterOrEqual(t, atomic.LoadInt32(&invitationEmailsSent), int32(2))
	mu.Lock()
	joinedHooks := strings.Join(hookEvents, ",")
	mu.Unlock()
	for _, expected := range []string{
		"beforeCreateOrg", "afterCreateOrg",
		"beforeUpdateOrg", "afterUpdateOrg",
		"beforeDeleteOrg", "afterDeleteOrg",
		"beforeAddMember", "afterAddMember",
		"beforeUpdateMemberRole", "afterUpdateMemberRole",
		"beforeRemoveMember", "afterRemoveMember",
		"beforeCreateInvitation", "afterCreateInvitation",
		"beforeAcceptInvitation", "afterAcceptInvitation",
		"beforeCreateTeam", "afterCreateTeam",
		"beforeUpdateTeam", "afterUpdateTeam",
		"beforeDeleteTeam", "afterDeleteTeam",
		"beforeAddTeamMember", "afterAddTeamMember",
		"beforeRemoveTeamMember", "afterRemoveTeamMember",
	} {
		require.Contains(t, joinedHooks, expected)
	}
}
