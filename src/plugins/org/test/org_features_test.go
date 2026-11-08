package org_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	coremodels "github.com/better-go-auth/goauth/src/models"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	orgdtos "github.com/better-go-auth/goauth/src/plugins/org/dtos"
	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
	orgerrors "github.com/better-go-auth/goauth/src/plugins/org/org-errors"
	gormorg "github.com/better-go-auth/goauth/src/plugins/org/repository/gorm"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/stretchr/testify/require"
)

// TestOrgConfig_AllowUserToCreateOrganization tests AllowUserToCreateOrganization flag and function.
func TestOrgConfig_AllowUserToCreateOrganization(t *testing.T) {
	ctx := context.Background()

	// Step 1: Test with AllowUserToCreateOrganization = false
	allowFalse := false
	env1, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		AllowUserToCreateOrganization: &allowFalse,
	})
	userID1, _ := setupOrgUser(t, env1, "allow-false@example.com", "", "")

	_, err := env1.OrgService.CreateOrganization(ctx, userID1, orgdtos.CreateOrgInput{
		Name: "Forbidden Org",
		Slug: "forbidden-org-1",
	})
	require.Error(t, err)
	require.True(t, errors.Is(err, orgerrors.ErrUserCannotCreateOrg))

	// Step 2: Test with AllowUserToCreateOrganizationFn returning false
	env2, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		AllowUserToCreateOrganizationFn: func(ctx context.Context, user *coremodels.User) (bool, error) {
			if user != nil && strings.Contains(user.Email, "pro") {
				return true, nil
			}
			return false, nil
		},
	})
	userIDFree, _ := setupOrgUser(t, env2, "free-user@example.com", "", "")
	userIDPro, _ := setupOrgUser(t, env2, "pro-user@example.com", "", "")

	// Free user should be rejected
	_, err = env2.OrgService.CreateOrganization(ctx, userIDFree, orgdtos.CreateOrgInput{
		Name: "Free Org",
		Slug: "free-org",
	})
	require.Error(t, err)
	require.True(t, errors.Is(err, orgerrors.ErrUserCannotCreateOrg))

	// Pro user should succeed
	proOrg, err := env2.OrgService.CreateOrganization(ctx, userIDPro, orgdtos.CreateOrgInput{
		Name: "Pro Org",
		Slug: "pro-org",
	})
	require.NoError(t, err)
	require.NotNil(t, proOrg)
}

// TestOrgConfig_OrganizationLimit tests organization creation limits (numeric and dynamic func).
func TestOrgConfig_OrganizationLimit(t *testing.T) {
	ctx := context.Background()

	// Step 1: Numeric OrganizationLimit = 1
	limit := 1
	env, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		OrganizationLimit: &limit,
	})
	userID, _ := setupOrgUser(t, env, "limit-user@example.com", "", "")

	// 1st org creation should succeed
	_, err := env.OrgService.CreateOrganization(ctx, userID, orgdtos.CreateOrgInput{
		Name: "First Org",
		Slug: "first-org",
	})
	require.NoError(t, err)

	// 2nd org creation should fail with ErrOrganizationLimitReached
	_, err = env.OrgService.CreateOrganization(ctx, userID, orgdtos.CreateOrgInput{
		Name: "Second Org",
		Slug: "second-org",
	})
	require.Error(t, err)
	require.True(t, errors.Is(err, orgerrors.ErrOrganizationLimitReached))

	// Step 2: Dynamic OrganizationLimitFn
	env2, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		OrganizationLimitFn: func(ctx context.Context, user *coremodels.User) (bool, error) {
			// Limit reached if user is not VIP
			return user == nil || !strings.Contains(user.Email, "vip"), nil
		},
	})
	userNonVIP, _ := setupOrgUser(t, env2, "standard@example.com", "", "")
	userVIP, _ := setupOrgUser(t, env2, "vip@example.com", "", "")

	// Non-VIP user should reach limit immediately
	_, err = env2.OrgService.CreateOrganization(ctx, userNonVIP, orgdtos.CreateOrgInput{
		Name: "Standard Org",
		Slug: "standard-org",
	})
	require.Error(t, err)
	require.True(t, errors.Is(err, orgerrors.ErrOrganizationLimitReached))

	// VIP user should succeed
	vipOrg, err := env2.OrgService.CreateOrganization(ctx, userVIP, orgdtos.CreateOrgInput{
		Name: "VIP Org",
		Slug: "vip-org",
	})
	require.NoError(t, err)
	require.NotNil(t, vipOrg)
}

// TestOrgConfig_CreatorRole tests configuring the creator role.
func TestOrgConfig_CreatorRole(t *testing.T) {
	ctx := context.Background()

	// Step 1: Setup environment with custom CreatorRole = "admin"
	env, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		CreatorRole: "admin",
	})
	userID, _ := setupOrgUser(t, env, "custom-creator@example.com", "", "")

	org, err := env.OrgService.CreateOrganization(ctx, userID, orgdtos.CreateOrgInput{
		Name: "Custom Role Org",
		Slug: "custom-role-org",
	})
	require.NoError(t, err)

	// Step 2: Verify creator member role is "admin"
	member, err := env.OrgService.GetMember(ctx, org.ID, userID)
	require.NoError(t, err)
	require.Equal(t, orgmodels.OrgMemberRole("admin"), member.Role)
}

// TestOrgConfig_MembershipLimit tests membership limits on invitation and acceptance.
func TestOrgConfig_MembershipLimit(t *testing.T) {
	ctx := context.Background()

	// Step 1: Setup environment with MembershipLimit = 1 (only the creator fits)
	limit := 1
	env, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		MembershipLimit: &limit,
	})
	ownerID, _ := setupOrgUser(t, env, "owner-mem@example.com", "", "")
	org, err := env.OrgService.CreateOrganization(ctx, ownerID, orgdtos.CreateOrgInput{
		Name: "Limit Org",
		Slug: "limit-org",
	})
	require.NoError(t, err)

	// Step 2: Inviting another member should fail because limit of 1 is already reached by owner
	_, err = env.OrgService.InviteMember(ctx, ownerID, orgdtos.InviteMemberInput{
		OrganizationID: org.ID,
		Email:          "invitee@example.com",
		Role:           orgmodels.OrgRoleMember,
	})
	require.Error(t, err)
	require.True(t, errors.Is(err, orgerrors.ErrMembershipLimitReached))

	// Step 3: Dynamic MembershipLimitFn
	env2, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		MembershipLimitFn: func(ctx context.Context, user *coremodels.User, org *orgmodels.Organization) (int, error) {
			return 1, nil // Enforce 1 member max
		},
	})
	ownerID2, _ := setupOrgUser(t, env2, "owner2@example.com", "", "")
	org2, err := env2.OrgService.CreateOrganization(ctx, ownerID2, orgdtos.CreateOrgInput{
		Name: "Dyn Limit Org",
		Slug: "dyn-limit-org",
	})
	require.NoError(t, err)

	_, err = env2.OrgService.InviteMember(ctx, ownerID2, orgdtos.InviteMemberInput{
		OrganizationID: org2.ID,
		Email:          "dyn-invitee@example.com",
		Role:           orgmodels.OrgRoleMember,
	})
	require.Error(t, err)
	require.True(t, errors.Is(err, orgerrors.ErrMembershipLimitReached))
}

// TestOrgConfig_InvitationLimit tests invitation limits.
func TestOrgConfig_InvitationLimit(t *testing.T) {
	ctx := context.Background()

	// Step 1: InvitationLimit = 1
	invLimit := 1
	memLimit := 10
	env, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		InvitationLimit: &invLimit,
		MembershipLimit: &memLimit,
	})
	ownerID, _ := setupOrgUser(t, env, "inv-owner@example.com", "", "")
	org, err := env.OrgService.CreateOrganization(ctx, ownerID, orgdtos.CreateOrgInput{
		Name: "Inv Limit Org",
		Slug: "inv-limit-org",
	})
	require.NoError(t, err)

	// 1st invitation should succeed
	_, err = env.OrgService.InviteMember(ctx, ownerID, orgdtos.InviteMemberInput{
		OrganizationID: org.ID,
		Email:          "invitee1@example.com",
		Role:           orgmodels.OrgRoleMember,
	})
	require.NoError(t, err)

	// 2nd invitation should fail with ErrInvitationLimitReached
	_, err = env.OrgService.InviteMember(ctx, ownerID, orgdtos.InviteMemberInput{
		OrganizationID: org.ID,
		Email:          "invitee2@example.com",
		Role:           orgmodels.OrgRoleMember,
	})
	require.Error(t, err)
	require.True(t, errors.Is(err, orgerrors.ErrInvitationLimitReached))
}

// TestOrgConfig_CancelPendingInvitationsOnReInvite tests re-invitation behavior.
func TestOrgConfig_CancelPendingInvitationsOnReInvite(t *testing.T) {
	ctx := context.Background()

	// Step 1: Default behavior (CancelPendingInvitationsOnReInvite = false)
	reinviteFalse := false
	env1, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		CancelPendingInvitationsOnReInvite: &reinviteFalse,
	})
	ownerID1, _ := setupOrgUser(t, env1, "reinvite1@example.com", "", "")
	org1, err := env1.OrgService.CreateOrganization(ctx, ownerID1, orgdtos.CreateOrgInput{
		Name: "Reinvite Org 1",
		Slug: "reinvite-org-1",
	})
	require.NoError(t, err)

	// 1st invite
	_, err = env1.OrgService.InviteMember(ctx, ownerID1, orgdtos.InviteMemberInput{
		OrganizationID: org1.ID,
		Email:          "target@example.com",
		Role:           orgmodels.OrgRoleMember,
	})
	require.NoError(t, err)

	// Re-invite when false should return ErrPendingInvitationExists
	_, err = env1.OrgService.InviteMember(ctx, ownerID1, orgdtos.InviteMemberInput{
		OrganizationID: org1.ID,
		Email:          "target@example.com",
		Role:           orgmodels.OrgRoleMember,
	})
	require.Error(t, err)
	require.True(t, errors.Is(err, orgerrors.ErrPendingInvitationExists))

	// Step 2: CancelPendingInvitationsOnReInvite = true
	reinviteTrue := true
	env2, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		CancelPendingInvitationsOnReInvite: &reinviteTrue,
	})
	ownerID2, _ := setupOrgUser(t, env2, "reinvite2@example.com", "", "")
	org2, err := env2.OrgService.CreateOrganization(ctx, ownerID2, orgdtos.CreateOrgInput{
		Name: "Reinvite Org 2",
		Slug: "reinvite-org-2",
	})
	require.NoError(t, err)

	// 1st invite
	inv1, err := env2.OrgService.InviteMember(ctx, ownerID2, orgdtos.InviteMemberInput{
		OrganizationID: org2.ID,
		Email:          "target@example.com",
		Role:           orgmodels.OrgRoleMember,
	})
	require.NoError(t, err)

	// Re-invite should cancel the first and create a new one
	inv2, err := env2.OrgService.InviteMember(ctx, ownerID2, orgdtos.InviteMemberInput{
		OrganizationID: org2.ID,
		Email:          "target@example.com",
		Role:           orgmodels.OrgRoleAdmin,
	})
	require.NoError(t, err)
	require.NotEqual(t, inv1.ID, inv2.ID)

	// Verify old invitation was canceled
	oldInv, err := env2.OrgService.GetInvitation(ctx, inv1.ID)
	require.NoError(t, err)
	require.Equal(t, orgmodels.InvitationCanceled, oldInv.Status)
}

// TestOrgConfig_RequireEmailVerificationOnInvitation tests requiring email verification for invitation actions.
func TestOrgConfig_RequireEmailVerificationOnInvitation(t *testing.T) {
	ctx := context.Background()

	// Step 1: Setup environment with RequireEmailVerificationOnInvitation = true
	reinvite := true
	env, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		RequireEmailVerificationOnInvitation: true,
		CancelPendingInvitationsOnReInvite:   &reinvite,
	})
	ownerID, _ := setupOrgUser(t, env, "verif-owner@example.com", "", "")
	org, err := env.OrgService.CreateOrganization(ctx, ownerID, orgdtos.CreateOrgInput{
		Name: "Verif Org",
		Slug: "verif-org",
	})
	require.NoError(t, err)

	// Create user with unverified email
	inviteeID, _ := setupOrgUser(t, env, "invitee-unverified@example.com", "", "")
	err = env.DB.Model(&coremodels.User{}).Where("id = ?", inviteeID).Update("email_verified", false).Error
	require.NoError(t, err)

	inv, err := env.OrgService.InviteMember(ctx, ownerID, orgdtos.InviteMemberInput{
		OrganizationID: org.ID,
		Email:          "invitee-unverified@example.com",
		Role:           orgmodels.OrgRoleMember,
	})
	require.NoError(t, err)

	// Step 2: Attempting to accept invitation with unverified email should fail
	err = env.OrgService.AcceptInvitation(ctx, inv.ID, inviteeID)
	require.Error(t, err)
	require.True(t, errors.Is(err, orgerrors.ErrEmailVerificationRequired))

	// Step 3: Verify the user's email in database
	err = env.DB.Model(&coremodels.User{}).Where("id = ?", inviteeID).Update("email_verified", true).Error
	require.NoError(t, err)

	// Step 4: Now accepting invitation should succeed
	err = env.OrgService.AcceptInvitation(ctx, inv.ID, inviteeID)
	require.NoError(t, err)
}

// TestOrgConfig_DisableOrganizationDeletion tests disabling org deletion.
func TestOrgConfig_DisableOrganizationDeletion(t *testing.T) {
	ctx := context.Background()

	// Step 1: Setup environment with DisableOrganizationDeletion = true
	env, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		DisableOrganizationDeletion: true,
	})
	ownerID, _ := setupOrgUser(t, env, "nodelete@example.com", "", "")
	org, err := env.OrgService.CreateOrganization(ctx, ownerID, orgdtos.CreateOrgInput{
		Name: "No Delete Org",
		Slug: "no-delete-org",
	})
	require.NoError(t, err)

	// Step 2: Attempting to delete the org should return ErrOrganizationDeletionDisabled
	err = env.OrgService.DeleteOrganization(ctx, org.ID, ownerID)
	require.Error(t, err)
	require.True(t, errors.Is(err, orgerrors.ErrOrganizationDeletionDisabled))
}

// TestOrgConfig_InvitationExpiresIn tests custom invitation expiration time.
func TestOrgConfig_InvitationExpiresIn(t *testing.T) {
	ctx := context.Background()

	// Step 1: Setup environment with InvitationExpiresIn = 2 hours
	customExpiry := 2 * time.Hour
	env, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		InvitaionConfig: orgconfig.InvitaionConfig{
			InvitationExpiresIn: customExpiry,
		},
	})
	ownerID, _ := setupOrgUser(t, env, "expiry-owner@example.com", "", "")
	org, err := env.OrgService.CreateOrganization(ctx, ownerID, orgdtos.CreateOrgInput{
		Name: "Expiry Org",
		Slug: "expiry-org",
	})
	require.NoError(t, err)

	// Step 2: Invite member and verify expiration is roughly now + 2 hours
	now := time.Now().UTC()
	inv, err := env.OrgService.InviteMember(ctx, ownerID, orgdtos.InviteMemberInput{
		OrganizationID: org.ID,
		Email:          "expiry-target@example.com",
		Role:           orgmodels.OrgRoleMember,
	})
	require.NoError(t, err)
	require.WithinDuration(t, now.Add(customExpiry), inv.ExpiresAt, 5*time.Second)
}

// TestOrgConfig_SendInvitationEmail tests the SendInvitationEmail callback.
func TestOrgConfig_SendInvitationEmail(t *testing.T) {
	ctx := context.Background()

	// Step 1: Setup environment with SendInvitationEmail callback
	var emailSent bool
	var sentInput orgconfig.SendInvitationInput
	env, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		InvitaionConfig: orgconfig.InvitaionConfig{
			SendInvitationEmail: func(ctx context.Context, input orgconfig.SendInvitationInput) error {
				emailSent = true
				sentInput = input
				return nil
			},
		},
	})
	ownerID, _ := setupOrgUser(t, env, "sender-owner@example.com", "", "")
	org, err := env.OrgService.CreateOrganization(ctx, ownerID, orgdtos.CreateOrgInput{
		Name: "Email Org",
		Slug: "email-org",
	})
	require.NoError(t, err)

	// Step 2: Send invite and verify email callback received proper data
	inv, err := env.OrgService.InviteMember(ctx, ownerID, orgdtos.InviteMemberInput{
		OrganizationID: org.ID,
		Email:          "recipient@example.com",
		Role:           orgmodels.OrgRoleMember,
	})
	require.NoError(t, err)
	require.True(t, emailSent)
	require.Equal(t, inv.ID, sentInput.ID)
	require.Equal(t, "recipient@example.com", sentInput.Email)
	require.Equal(t, org.ID, sentInput.Organization.ID)
}

// TestOrgConfig_CustomRoles tests custom static roles in HasPermission.
func TestOrgConfig_CustomRoles(t *testing.T) {
	ctx := context.Background()

	// Step 1: Configure custom static roles
	env, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		Roles: map[string]orgmodels.Permission{
			"editor": {
				"article": []string{"read", "edit"},
			},
		},
	})

	// Step 2: Check permissions
	hasEdit, err := env.OrgService.HasPermission(ctx, "org-id", "editor", "article", "edit")
	require.NoError(t, err)
	require.True(t, hasEdit)

	hasDelete, err := env.OrgService.HasPermission(ctx, "org-id", "editor", "article", "delete")
	require.NoError(t, err)
	require.False(t, hasDelete)
}

// TestOrgConfig_DynamicAccessControl_MaximumRoles tests role count limits in dynamic access control.
func TestOrgConfig_DynamicAccessControl_MaximumRoles(t *testing.T) {
	ctx := context.Background()

	// Step 1: MaximumRolesPerOrganization = 1
	maxRoles := 1
	env, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		DynamicAccessControl: &orgconfig.DynamicAccessControlConfig{
			Enabled:                     true,
			MaximumRolesPerOrganization: &maxRoles,
		},
	})
	ownerID, _ := setupOrgUser(t, env, "dac-owner@example.com", "", "")
	org, err := env.OrgService.CreateOrganization(ctx, ownerID, orgdtos.CreateOrgInput{
		Name: "DAC Org",
		Slug: "dac-org",
	})
	require.NoError(t, err)

	// 1st role creation succeeds
	_, err = env.OrgService.CreateRole(ctx, org.ID, "role-1", orgmodels.Permission{"doc": []string{"read"}}, ownerID)
	require.NoError(t, err)

	// 2nd role creation should fail with ErrMaximumRolesReached
	_, err = env.OrgService.CreateRole(ctx, org.ID, "role-2", orgmodels.Permission{"doc": []string{"write"}}, ownerID)
	require.Error(t, err)
	require.True(t, errors.Is(err, orgerrors.ErrMaximumRolesReached))
}

// TestOrgConfig_Teams_CustomDefaultTeam tests custom default team creation.
func TestOrgConfig_Teams_CustomDefaultTeam(t *testing.T) {
	ctx := context.Background()

	// Step 1: Setup environment with CustomCreateDefaultTeam
	db := helpers.SetupTestDB(t, helpers.DBTypeSQLite)
	customCreated := false
	enabled := true
	env, _ := setupTeamsEnvWithDB(t, db, orgconfig.OrgConfig{
		Teams: &orgconfig.TeamsConfig{
			Enabled: true,
			DefaultTeam: &orgconfig.DefaultTeamConfig{
				Enabled: &enabled,
				CustomCreateDefaultTeam: func(ctx context.Context, org *orgmodels.Organization) (*orgmodels.Team, error) {
					customCreated = true
					now := coremodels.TimeNow()
					team := &orgmodels.Team{
						Base:           coremodels.Base{ID: coremodels.NewID(), CreatedAt: now, UpdatedAt: now},
						Name:           "Core Engineering",
						OrganizationID: org.ID,
					}
					return gormorg.NewTeamRepo(db).CreateTeam(ctx, team)
				},
			},
		},
	})
	ownerID, _ := setupOrgUser(t, env, "custom-team-owner@example.com", "", "")

	// Step 2: Create org and verify custom default team was created
	org, err := env.OrgService.CreateOrganization(ctx, ownerID, orgdtos.CreateOrgInput{
		Name: "Eng Org",
		Slug: "eng-org",
	})
	require.NoError(t, err)
	require.True(t, customCreated)

	teams, count, err := env.OrgService.ListTeams(ctx, org.ID, ownerID, orgmodels.Pagination{})
	require.NoError(t, err)
	require.Equal(t, int64(1), count)
	require.Equal(t, "Core Engineering", teams[0].Name)
}

// TestOrgConfig_OrganizationHooks tests lifecycle hooks for orgs, members, invitations, and teams.
func TestOrgConfig_OrganizationHooks(t *testing.T) {
	ctx := context.Background()

	var (
		beforeCreateOrgCalled      bool
		afterCreateOrgCalled       bool
		beforeUpdateOrgCalled      bool
		afterUpdateOrgCalled       bool
		beforeDeleteOrgCalled      bool
		afterDeleteOrgCalled       bool
		beforeCreateInviteCalled   bool
		afterCreateInviteCalled    bool
		beforeAcceptInviteCalled   bool
		afterAcceptInviteCalled    bool
		beforeAddMemberCalled      bool
		afterAddMemberCalled       bool
		beforeUpdateMemberRoleCalled bool
		afterUpdateMemberRoleCalled  bool
		beforeRemoveMemberCalled   bool
		afterRemoveMemberCalled    bool
		beforeCreateTeamCalled     bool
		afterCreateTeamCalled      bool
		beforeUpdateTeamCalled     bool
		afterUpdateTeamCalled      bool
		beforeDeleteTeamCalled     bool
		afterDeleteTeamCalled      bool
		beforeAddTeamMemberCalled  bool
		afterAddTeamMemberCalled   bool
		beforeRemoveTeamMemberCalled bool
		afterRemoveTeamMemberCalled  bool
	)

	reinvite := true
	allowRemoveAllTeams := true
	hooks := orgconfig.OrganizationHooks{
		// Org hooks
		BeforeCreateOrganization: func(ctx context.Context, data orgconfig.BeforeCreateOrgData) (*orgdtos.CreateOrgInput, error) {
			beforeCreateOrgCalled = true
			data.Organization.Name = data.Organization.Name + " (Modified)"
			return &data.Organization, nil
		},
		AfterCreateOrganization: func(ctx context.Context, data orgconfig.AfterCreateOrgData) error {
			afterCreateOrgCalled = true
			return nil
		},
		BeforeUpdateOrganization: func(ctx context.Context, data orgconfig.BeforeUpdateOrgData) (*orgdtos.UpdateOrgInput, error) {
			beforeUpdateOrgCalled = true
			return nil, nil
		},
		AfterUpdateOrganization: func(ctx context.Context, data orgconfig.AfterUpdateOrgData) error {
			afterUpdateOrgCalled = true
			return nil
		},
		BeforeDeleteOrganization: func(ctx context.Context, data orgconfig.BeforeDeleteOrgData) error {
			beforeDeleteOrgCalled = true
			return nil
		},
		AfterDeleteOrganization: func(ctx context.Context, data orgconfig.AfterDeleteOrgData) error {
			afterDeleteOrgCalled = true
			return nil
		},

		// Member hooks
		BeforeAddMember: func(ctx context.Context, data orgconfig.BeforeAddMemberData) (*orgmodels.Member, error) {
			beforeAddMemberCalled = true
			return nil, nil
		},
		AfterAddMember: func(ctx context.Context, data orgconfig.AfterAddMemberData) error {
			afterAddMemberCalled = true
			return nil
		},
		BeforeUpdateMemberRole: func(ctx context.Context, data orgconfig.BeforeUpdateMemberRoleData) (*string, error) {
			beforeUpdateMemberRoleCalled = true
			return nil, nil
		},
		AfterUpdateMemberRole: func(ctx context.Context, data orgconfig.AfterUpdateMemberRoleData) error {
			afterUpdateMemberRoleCalled = true
			return nil
		},
		BeforeRemoveMember: func(ctx context.Context, data orgconfig.BeforeRemoveMemberData) error {
			beforeRemoveMemberCalled = true
			return nil
		},
		AfterRemoveMember: func(ctx context.Context, data orgconfig.AfterRemoveMemberData) error {
			afterRemoveMemberCalled = true
			return nil
		},

		// Invitation hooks
		BeforeCreateInvitation: func(ctx context.Context, data orgconfig.BeforeCreateInvitationData) (*orgdtos.InviteMemberInput, error) {
			beforeCreateInviteCalled = true
			return nil, nil
		},
		AfterCreateInvitation: func(ctx context.Context, data orgconfig.AfterCreateInvitationData) error {
			afterCreateInviteCalled = true
			return nil
		},
		BeforeAcceptInvitation: func(ctx context.Context, data orgconfig.BeforeAcceptInvitationData) error {
			beforeAcceptInviteCalled = true
			return nil
		},
		AfterAcceptInvitation: func(ctx context.Context, data orgconfig.AfterAcceptInvitationData) error {
			afterAcceptInviteCalled = true
			return nil
		},

		// Team hooks
		BeforeCreateTeam: func(ctx context.Context, data orgconfig.BeforeCreateTeamData) (*orgdtos.CreateTeamInput, error) {
			beforeCreateTeamCalled = true
			return nil, nil
		},
		AfterCreateTeam: func(ctx context.Context, data orgconfig.AfterCreateTeamData) error {
			afterCreateTeamCalled = true
			return nil
		},
		BeforeUpdateTeam: func(ctx context.Context, data orgconfig.BeforeUpdateTeamData) (*orgdtos.UpdateTeamInput, error) {
			beforeUpdateTeamCalled = true
			return nil, nil
		},
		AfterUpdateTeam: func(ctx context.Context, data orgconfig.AfterUpdateTeamData) error {
			afterUpdateTeamCalled = true
			return nil
		},
		BeforeDeleteTeam: func(ctx context.Context, data orgconfig.BeforeDeleteTeamData) error {
			beforeDeleteTeamCalled = true
			return nil
		},
		AfterDeleteTeam: func(ctx context.Context, data orgconfig.AfterDeleteTeamData) error {
			afterDeleteTeamCalled = true
			return nil
		},
		BeforeAddTeamMember: func(ctx context.Context, data orgconfig.BeforeAddTeamMemberData) (*orgdtos.AddTeamMemberInput, error) {
			beforeAddTeamMemberCalled = true
			return nil, nil
		},
		AfterAddTeamMember: func(ctx context.Context, data orgconfig.AfterAddTeamMemberData) error {
			afterAddTeamMemberCalled = true
			return nil
		},
		BeforeRemoveTeamMember: func(ctx context.Context, data orgconfig.BeforeRemoveTeamMemberData) error {
			beforeRemoveTeamMemberCalled = true
			return nil
		},
		AfterRemoveTeamMember: func(ctx context.Context, data orgconfig.AfterRemoveTeamMemberData) error {
			afterRemoveTeamMemberCalled = true
			return nil
		},
	}

	env, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		OrganizationHooks:                  hooks,
		CancelPendingInvitationsOnReInvite: &reinvite,
		Teams: &orgconfig.TeamsConfig{
			Enabled:               true,
			AllowRemovingAllTeams: allowRemoveAllTeams,
		},
	})

	ownerID, _ := setupOrgUser(t, env, "hooks-owner@example.com", "", "")

	// 1. Create Org
	org, err := env.OrgService.CreateOrganization(ctx, ownerID, orgdtos.CreateOrgInput{
		Name: "Hooked Org",
		Slug: "hooked-org",
	})
	require.NoError(t, err)
	require.True(t, beforeCreateOrgCalled)
	require.True(t, afterCreateOrgCalled)
	require.Equal(t, "Hooked Org (Modified)", org.Name)

	// 2. Update Org
	newName := "Hooked Org Renamed"
	_, err = env.OrgService.UpdateOrganization(ctx, org.ID, orgdtos.UpdateOrgInput{
		Name: &newName,
	}, ownerID)
	require.NoError(t, err)
	require.True(t, beforeUpdateOrgCalled)
	require.True(t, afterUpdateOrgCalled)

	// 3. Create & Accept Invitation (which triggers AddMember)
	inviteeID, _ := setupOrgUser(t, env, "hook-invitee@example.com", "", "")
	inv, err := env.OrgService.InviteMember(ctx, ownerID, orgdtos.InviteMemberInput{
		OrganizationID: org.ID,
		Email:          "hook-invitee@example.com",
		Role:           orgmodels.OrgRoleMember,
	})
	require.NoError(t, err)
	require.True(t, beforeCreateInviteCalled)
	require.True(t, afterCreateInviteCalled)

	err = env.OrgService.AcceptInvitation(ctx, inv.ID, inviteeID)
	require.NoError(t, err)
	require.True(t, beforeAcceptInviteCalled)
	require.True(t, afterAcceptInviteCalled)
	require.True(t, beforeAddMemberCalled)
	require.True(t, afterAddMemberCalled)

	// 4. Update Member Role
	member, err := env.OrgService.GetMember(ctx, org.ID, inviteeID)
	require.NoError(t, err)
	_, err = env.OrgService.UpdateMemberRole(ctx, orgdtos.UpdateMemberRoleInput{
		OrganizationID: org.ID,
		MemberID:       member.ID,
		Role:           orgmodels.OrgRoleAdmin,
	}, ownerID)
	require.NoError(t, err)
	require.True(t, beforeUpdateMemberRoleCalled)
	require.True(t, afterUpdateMemberRoleCalled)

	// 5. Teams operations
	team, err := env.OrgService.CreateTeam(ctx, orgdtos.CreateTeamInput{
		OrganizationID: org.ID,
		Name:           "Hook Team",
	}, ownerID)
	require.NoError(t, err)
	require.True(t, beforeCreateTeamCalled)
	require.True(t, afterCreateTeamCalled)

	_, err = env.OrgService.UpdateTeam(ctx, orgdtos.UpdateTeamInput{
		TeamID: team.ID,
		Name:   "Hook Team Updated",
	}, ownerID)
	require.NoError(t, err)
	require.True(t, beforeUpdateTeamCalled)
	require.True(t, afterUpdateTeamCalled)

	// Add team member
	_, err = env.OrgService.AddTeamMember(ctx, orgdtos.AddTeamMemberInput{
		TeamID: team.ID,
		UserID: inviteeID,
	}, ownerID)
	require.NoError(t, err)
	require.True(t, beforeAddTeamMemberCalled)
	require.True(t, afterAddTeamMemberCalled)

	// Remove team member
	err = env.OrgService.RemoveTeamMember(ctx, orgdtos.RemoveTeamMemberInput{
		TeamID: team.ID,
		UserID: inviteeID,
	}, ownerID)
	require.NoError(t, err)
	require.True(t, beforeRemoveTeamMemberCalled)
	require.True(t, afterRemoveTeamMemberCalled)

	// Delete team
	err = env.OrgService.DeleteTeam(ctx, orgdtos.DeleteTeamInput{
		TeamID: team.ID,
	}, ownerID)
	require.NoError(t, err)
	require.True(t, beforeDeleteTeamCalled)
	require.True(t, afterDeleteTeamCalled)

	// 6. Remove Member
	err = env.OrgService.RemoveMember(ctx, orgdtos.RemoveMemberInput{
		OrganizationID: org.ID,
		MemberID:       member.ID,
	}, ownerID)
	require.NoError(t, err)
	require.True(t, beforeRemoveMemberCalled)
	require.True(t, afterRemoveMemberCalled)

	// 7. Delete Org
	err = env.OrgService.DeleteOrganization(ctx, org.ID, ownerID)
	require.NoError(t, err)
	require.True(t, beforeDeleteOrgCalled)
	require.True(t, afterDeleteOrgCalled)
}
