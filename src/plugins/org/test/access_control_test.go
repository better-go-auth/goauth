package org_test

import (
	"context"
	"testing"

	humatypes "github.com/better-go-auth/goauth/src/common/types"
	coremodels "github.com/better-go-auth/goauth/src/models"
	humaorg "github.com/better-go-auth/goauth/src/plugins/org/adapters/huma"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	orgdtos "github.com/better-go-auth/goauth/src/plugins/org/dtos"
	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
	"github.com/better-go-auth/goauth/src/providers/access"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/stretchr/testify/require"
)

// addMember inserts a member row with an arbitrary (possibly multi-role) role.
func addMember(t *testing.T, env *helpers.TestEnv, orgID, userID, role string) *orgmodels.Member {
	t.Helper()
	now := coremodels.TimeNow()
	m := &orgmodels.Member{
		Base:           coremodels.Base{ID: coremodels.NewID(), CreatedAt: now, UpdatedAt: now},
		OrganizationID: orgID,
		UserID:         userID,
		Role:           orgmodels.OrgMemberRole(role),
	}
	require.NoError(t, env.DB.Create(m).Error)
	return m
}

func setMemberRole(t *testing.T, env *helpers.TestEnv, m *orgmodels.Member, role string) {
	t.Helper()
	require.NoError(t, env.DB.Model(m).Update("role", role).Error)
}

func authOf(hdr map[string]string) humatypes.AuthHeaders {
	return humatypes.AuthHeaders{Authorization: hdr["Authorization"]}
}

func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	require.Error(t, err)
	require.Contains(t, err.Error(), code)
}

// betterAuthACConfig mirrors a typical better-auth server config with a custom "project" statement.
func betterAuthACConfig() orgconfig.OrgConfig {
	statements := orgconfig.DefaultStatements.Clone()
	statements["project"] = []string{"create", "read", "delete"}
	ac := access.NewAccessControl(statements)
	return orgconfig.OrgConfig{
		DynamicAccessControl: &orgconfig.DynamicAccessControlConfig{Enabled: true},
		AccessControl:        ac,
		AccessRoles: map[string]access.Role{
			"owner":  ac.NewRole(orgconfig.OwnerAC.Statements().Merge(access.Statements{"project": {"create", "read", "delete"}})),
			"admin":  ac.NewRole(orgconfig.AdminAC.Statements().Merge(access.Statements{"project": {"create", "read"}})),
			"member": ac.NewRole(orgconfig.MemberAC.Statements()),
		},
	}
}

// TestOrgAccessControl_RoleCRUDRoutes exercises better-auth's role CRUD and has-permission routes.
func TestOrgAccessControl_RoleCRUDRoutes(t *testing.T) {
	env, _ := setupTeamsEnv(t, betterAuthACConfig())
	h := env.OrgHandler
	ctx := context.Background()

	// Step 1: org with owner, admin and plain member
	ownerID, ownerHdr := setupOrgUser(t, env, "ac-owner@example.com", "", "")
	adminID, adminHdr := setupOrgUser(t, env, "ac-admin@example.com", "", "")
	memberID, memberHdr := setupOrgUser(t, env, "ac-member@example.com", "", "")
	_, outsiderHdr := setupOrgUser(t, env, "ac-outsider@example.com", "", "")
	org, err := env.OrgService.CreateOrganization(ctx, ownerID, orgdtos.CreateOrgInput{Name: "AC Org", Slug: "ac-org"})
	require.NoError(t, err)
	addMember(t, env, org.ID, adminID, "admin")
	member := addMember(t, env, org.ID, memberID, "member")

	// Step 2: admin creates a role; the name is lowercased and statements are returned
	created, err := h.CreateRole(ctx, &humaorg.CreateRoleInput{AuthHeaders: authOf(adminHdr), Body: orgdtos.CreateRoleInput{
		OrganizationID: org.ID, Role: "Editor", Permission: map[string][]string{"project": {"read"}},
	}})
	require.NoError(t, err)
	require.True(t, created.Body.Success)
	require.Equal(t, "editor", created.Body.RoleData.Role)
	require.Equal(t, map[string][]string{"project": {"read"}}, created.Body.Statements)

	// Step 3: better-auth checks on create
	_, err = h.CreateRole(ctx, &humaorg.CreateRoleInput{AuthHeaders: authOf(adminHdr), Body: orgdtos.CreateRoleInput{
		OrganizationID: org.ID, Role: "deleter", Permission: map[string][]string{"project": {"delete"}},
	}})
	requireCode(t, err, "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE") // privilege escalation
	_, err = h.CreateRole(ctx, &humaorg.CreateRoleInput{AuthHeaders: authOf(adminHdr), Body: orgdtos.CreateRoleInput{
		OrganizationID: org.ID, Role: "biller", Permission: map[string][]string{"billing": {"read"}},
	}})
	requireCode(t, err, "INVALID_RESOURCE")
	_, err = h.CreateRole(ctx, &humaorg.CreateRoleInput{AuthHeaders: authOf(adminHdr), Body: orgdtos.CreateRoleInput{
		OrganizationID: org.ID, Role: "Admin", Permission: map[string][]string{"project": {"read"}},
	}})
	requireCode(t, err, "ROLE_NAME_IS_ALREADY_TAKEN") // predefined
	_, err = h.CreateRole(ctx, &humaorg.CreateRoleInput{AuthHeaders: authOf(adminHdr), Body: orgdtos.CreateRoleInput{
		OrganizationID: org.ID, Role: "editor", Permission: map[string][]string{"project": {"read"}},
	}})
	requireCode(t, err, "ROLE_NAME_IS_ALREADY_TAKEN") // dynamic
	_, err = h.CreateRole(ctx, &humaorg.CreateRoleInput{AuthHeaders: authOf(memberHdr), Body: orgdtos.CreateRoleInput{
		OrganizationID: org.ID, Role: "x", Permission: map[string][]string{},
	}})
	requireCode(t, err, "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE") // member lacks ac:create
	_, err = h.CreateRole(ctx, &humaorg.CreateRoleInput{AuthHeaders: authOf(outsiderHdr), Body: orgdtos.CreateRoleInput{
		OrganizationID: org.ID, Role: "x", Permission: map[string][]string{},
	}})
	requireCode(t, err, "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION")

	// Step 4: members (ac:read) can list and get roles, by name or id
	list, err := h.ListRoles(ctx, &humaorg.ListRolesInput{AuthHeaders: authOf(memberHdr), OrganizationID: org.ID})
	require.NoError(t, err)
	require.Len(t, list.Body, 1)
	got, err := h.GetRole(ctx, &humaorg.GetRoleInput{AuthHeaders: authOf(memberHdr), OrganizationID: org.ID, RoleID: created.Body.RoleData.ID})
	require.NoError(t, err)
	require.Equal(t, "editor", got.Body.Role)
	_, err = h.GetRole(ctx, &humaorg.GetRoleInput{AuthHeaders: authOf(memberHdr), OrganizationID: org.ID, RoleName: "ghost"})
	requireCode(t, err, "ROLE_NOT_FOUND")

	// Step 5: has-permission with a multi-role member (member,editor)
	setMemberRole(t, env, member, "member,editor")
	hp, err := h.HasPermission(ctx, &humaorg.HasPermissionInput{AuthHeaders: authOf(memberHdr), Body: orgdtos.HasPermissionInput{
		OrganizationID: org.ID, Permissions: map[string][]string{"project": {"read"}},
	}})
	require.NoError(t, err)
	require.True(t, hp.Body.Success)
	require.Nil(t, hp.Body.Error)
	hp, err = h.HasPermission(ctx, &humaorg.HasPermissionInput{AuthHeaders: authOf(memberHdr), Body: orgdtos.HasPermissionInput{
		OrganizationID: org.ID, Permissions: map[string][]string{"project": {"read", "create"}},
	}})
	require.NoError(t, err)
	require.False(t, hp.Body.Success)
	_, err = h.HasPermission(ctx, &humaorg.HasPermissionInput{AuthHeaders: authOf(outsiderHdr), Body: orgdtos.HasPermissionInput{
		OrganizationID: org.ID, Permissions: map[string][]string{"project": {"read"}},
	}})
	requireCode(t, err, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
	// owner has no blanket bypass in better-auth mode, only its role statements
	hp, err = h.HasPermission(ctx, &humaorg.HasPermissionInput{AuthHeaders: authOf(ownerHdr), Body: orgdtos.HasPermissionInput{
		OrganizationID: org.ID, Permissions: map[string][]string{"project": {"delete"}, "organization": {"delete"}},
	}})
	require.NoError(t, err)
	require.True(t, hp.Body.Success)

	// Step 6: update-role renames (lowercased) and re-checks escalation
	upd, err := h.UpdateRole(ctx, &humaorg.UpdateRoleInput{AuthHeaders: authOf(adminHdr), Body: orgdtos.UpdateRoleInput{
		OrganizationID: org.ID, RoleName: "editor", Data: orgdtos.UpdateRoleData{RoleName: "Writer", Permission: map[string][]string{"project": {"read", "create"}}},
	}})
	require.NoError(t, err)
	require.Equal(t, "writer", upd.Body.RoleData.Role)
	require.Equal(t, orgmodels.Permission{"project": {"read", "create"}}, upd.Body.RoleData.Permission)
	_, err = h.UpdateRole(ctx, &humaorg.UpdateRoleInput{AuthHeaders: authOf(adminHdr), Body: orgdtos.UpdateRoleInput{
		OrganizationID: org.ID, RoleName: "writer", Data: orgdtos.UpdateRoleData{Permission: map[string][]string{"project": {"delete"}}},
	}})
	requireCode(t, err, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE")
	_, err = h.UpdateRole(ctx, &humaorg.UpdateRoleInput{AuthHeaders: authOf(adminHdr), Body: orgdtos.UpdateRoleInput{
		OrganizationID: org.ID, RoleName: "writer", Data: orgdtos.UpdateRoleData{RoleName: "owner"},
	}})
	requireCode(t, err, "ROLE_NAME_IS_ALREADY_TAKEN")

	// Step 7: delete-role guards
	setMemberRole(t, env, member, "member,writer")
	_, err = h.DeleteRole(ctx, &humaorg.DeleteRoleInput{AuthHeaders: authOf(adminHdr), Body: orgdtos.DeleteRoleInput{OrganizationID: org.ID, RoleName: "writer"}})
	requireCode(t, err, "ROLE_IS_ASSIGNED_TO_MEMBERS")
	_, err = h.DeleteRole(ctx, &humaorg.DeleteRoleInput{AuthHeaders: authOf(adminHdr), Body: orgdtos.DeleteRoleInput{OrganizationID: org.ID, RoleName: "member"}})
	requireCode(t, err, "CANNOT_DELETE_A_PRE_DEFINED_ROLE")
	_, err = h.DeleteRole(ctx, &humaorg.DeleteRoleInput{AuthHeaders: authOf(memberHdr), Body: orgdtos.DeleteRoleInput{OrganizationID: org.ID, RoleName: "writer"}})
	requireCode(t, err, "YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE")
	setMemberRole(t, env, member, "member")
	del, err := h.DeleteRole(ctx, &humaorg.DeleteRoleInput{AuthHeaders: authOf(adminHdr), Body: orgdtos.DeleteRoleInput{OrganizationID: org.ID, RoleID: upd.Body.RoleData.ID}})
	require.NoError(t, err)
	require.True(t, del.Body.Success)
}

// TestOrgAccessControl_DynamicRolesMergeIntoPredefined checks better-auth's merge (not replace).
func TestOrgAccessControl_DynamicRolesMergeIntoPredefined(t *testing.T) {
	env, _ := setupTeamsEnv(t, betterAuthACConfig())
	ctx := context.Background()
	ownerID, _ := setupOrgUser(t, env, "merge-owner@example.com", "", "")
	org, err := env.OrgService.CreateOrganization(ctx, ownerID, orgdtos.CreateOrgInput{Name: "Merge Org", Slug: "merge-org"})
	require.NoError(t, err)

	// Step 1: a DB row named like a predefined role adds statements to it
	now := coremodels.TimeNow()
	require.NoError(t, env.DB.Create(&orgmodels.OrganizationRole{
		Base: coremodels.Base{ID: coremodels.NewID(), CreatedAt: now, UpdatedAt: now}, OrganizationID: org.ID,
		Role: "member", Permission: orgmodels.Permission{"project": {"read"}},
	}).Error)

	// Step 2: member keeps ac:read (predefined) and gains project:read (dynamic)
	ok, err := env.OrgService.HasPermissions(ctx, org.ID, "member", access.Req(map[string][]string{"ac": {"read"}, "project": {"read"}}))
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = env.OrgService.HasPermission(ctx, org.ID, "member", "project", "delete")
	require.NoError(t, err)
	require.False(t, ok)
}

// TestOrgAccessControl_LegacyDefaults keeps goauth's legacy rules when no AC is configured.
func TestOrgAccessControl_LegacyDefaults(t *testing.T) {
	env, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		// this test covers goauth's legacy permission rules (custom resources, owner bypass)
		GoAuth:               orgconfig.OrgGoAuth{LegacyPermissions: true},
		DynamicAccessControl: &orgconfig.DynamicAccessControlConfig{Enabled: true},
	})
	h := env.OrgHandler
	ctx := context.Background()
	ownerID, ownerHdr := setupOrgUser(t, env, "lg-owner@example.com", "", "")
	adminID, adminHdr := setupOrgUser(t, env, "lg-admin@example.com", "", "")
	memberID, memberHdr := setupOrgUser(t, env, "lg-member@example.com", "", "")
	org, err := env.OrgService.CreateOrganization(ctx, ownerID, orgdtos.CreateOrgInput{Name: "Legacy Org", Slug: "legacy-org"})
	require.NoError(t, err)
	addMember(t, env, org.ID, adminID, "admin")
	member := addMember(t, env, org.ID, memberID, "member")

	// Step 1: owner bypass and "*" wildcards still work
	_, err = h.CreateRole(ctx, &humaorg.CreateRoleInput{AuthHeaders: authOf(ownerHdr), Body: orgdtos.CreateRoleInput{
		OrganizationID: org.ID, Role: "Ops", Permission: map[string][]string{"servers": {"*"}},
	}})
	require.NoError(t, err)
	ok, err := env.OrgService.HasPermission(ctx, org.ID, "ops", "servers", "reboot")
	require.NoError(t, err)
	require.True(t, ok)

	// Step 2: built-in admin keeps its legacy rights (incl. ac:create), member does not
	_, err = h.CreateRole(ctx, &humaorg.CreateRoleInput{AuthHeaders: authOf(adminHdr), Body: orgdtos.CreateRoleInput{
		OrganizationID: org.ID, Role: "viewer", Permission: map[string][]string{"servers": {"read"}},
	}})
	require.NoError(t, err)
	_, err = h.CreateRole(ctx, &humaorg.CreateRoleInput{AuthHeaders: authOf(memberHdr), Body: orgdtos.CreateRoleInput{
		OrganizationID: org.ID, Role: "x", Permission: map[string][]string{},
	}})
	requireCode(t, err, "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE")
	ok, err = env.OrgService.HasPermission(ctx, org.ID, "admin", "organization", "delete")
	require.NoError(t, err)
	require.False(t, ok)

	// Step 3: multi-role members and the operation route check for a custom role
	setMemberRole(t, env, member, "member,ops")
	ok, err = env.OrgService.HasPermission(ctx, org.ID, "member,ops", "servers", "stop")
	require.NoError(t, err)
	require.True(t, ok)
	_, err = h.CreateRole(ctx, &humaorg.CreateRoleInput{AuthHeaders: authOf(ownerHdr), Body: orgdtos.CreateRoleInput{
		OrganizationID: org.ID, Role: "inviter", Permission: map[string][]string{"invitation": {"create"}},
	}})
	require.NoError(t, err)
	_, _, err = h.RequireOrgOp(ctx, authOf(memberHdr), org.ID, humaorg.OrInviteMember)
	requireCode(t, err, "FORBIDDEN") // plain member,ops cannot invite
	setMemberRole(t, env, member, "member,inviter")
	_, _, err = h.RequireOrgOp(ctx, authOf(memberHdr), org.ID, humaorg.OrInviteMember)
	require.NoError(t, err) // the dynamic role grants invitation:create
	_, _, err = h.RequireOrgOp(ctx, authOf(adminHdr), org.ID, humaorg.OrUpdateMemberRole)
	requireCode(t, err, "FORBIDDEN") // legacy table: only owner may update member roles

	// Step 4: has-permission route in legacy mode
	hp, err := h.HasPermission(ctx, &humaorg.HasPermissionInput{AuthHeaders: authOf(ownerHdr), Body: orgdtos.HasPermissionInput{
		OrganizationID: org.ID, Permission: map[string][]string{"anything": {"at-all"}},
	}})
	require.NoError(t, err)
	require.True(t, hp.Body.Success)
}
