package org_test

import (
	"context"
	"net/http"
	"testing"

	goauth "github.com/better-go-auth/goauth"
	serv_interfaces "github.com/better-go-auth/goauth/src/app/services/interfaces"
	loc_conf "github.com/better-go-auth/goauth/src/config"
	coremodels "github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/enums"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/org"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	orgdtos "github.com/better-go-auth/goauth/src/plugins/org/dtos"
	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
	humaorg "github.com/better-go-auth/goauth/src/plugins/org/adapters/huma"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func setupTeamsEnv(t *testing.T, cfg orgconfig.OrgConfig) (*helpers.TestEnv, *org.OrgPlugin) {
	t.Helper()
	dbName := "file:memdb_teams_" + uuid.New().String() + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)

	orgPlugin, err := org.NewWithGorm(db, cfg)
	require.NoError(t, err)

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("Teams Test API", "1.0.0"))
	store := sec_storage.New()

	auth, err := goauth.SetupGoAuth(context.Background(), api, goauth.GoAuthOptions{
		Conn:             db,
		SecondaryStorage: store,
		AuthConfig: loc_conf.AuthConfig{
			Secret: "secret-key-32-chars-long-for-test!",
			TrustedOrigins: []string{"http://127.0.0.1:*", "http://localhost:*"},
		},
		Plugins: []plugin.Plugin{orgPlugin},
	})
	require.NoError(t, err)

	env := &helpers.TestEnv{
		DB:         db,
		Auth:       auth,
		HumaAPI:    api,
		Mux:        mux,
		OrgHandler: orgPlugin.Handler(),
		OrgService: orgPlugin.Service(),
	}
	return env, orgPlugin
}

func TestOrgTeams_Disabled(t *testing.T) {
	env, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		Teams: &orgconfig.TeamsConfig{Enabled: false},
	})

	ownerID, _ := setupOrgUser(t, env, "disabled-owner@example.com", "", "")

	// Direct service call should return ErrTeamsDisabled
	_, err := env.OrgService.CreateTeam(context.Background(), orgdtos.CreateTeamInput{
		OrganizationID: "some-org",
		Name:           "Devs",
	}, ownerID)
	require.Error(t, err)
	require.False(t, env.OrgService.TeamsEnabled())
}

func TestOrgTeams_FullLifecycle(t *testing.T) {
	maxTeams := 3
	maxMembers := 2
	allowRemoveAll := false
	defaultTeam := true

	env, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		Teams: &orgconfig.TeamsConfig{
			Enabled:               true,
			DefaultTeam:           &defaultTeam,
			MaximumTeams:          &maxTeams,
			MaximumMembersPerTeam: &maxMembers,
			AllowRemovingAllTeams: allowRemoveAll,
		},
	})

	ctx := context.Background()
	ownerID, _ := setupOrgUser(t, env, "team-owner@example.com", "", "")
	memberID, _ := setupOrgUser(t, env, "team-member@example.com", "", "")
	outsiderID, _ := setupOrgUser(t, env, "outsider@example.com", "", "")

	// 1. Create Organization -> triggers default team creation
	createdOrg, err := env.OrgService.CreateOrganization(ctx, ownerID, orgdtos.CreateOrgInput{
		Name: "Engineering Corp",
		Slug: "engineering-corp",
	})
	require.NoError(t, err)
	require.NotEmpty(t, createdOrg.ID)

	// Add member to org
	_, err = env.OrgService.InviteMember(ctx, ownerID, orgdtos.InviteMemberInput{
		OrganizationID: createdOrg.ID,
		Email:          "team-member@example.com",
		Role:           "member",
	})
	require.NoError(t, err)

	invs, total, err := env.OrgService.ListInvitations(ctx, createdOrg.ID, orgmodels.Pagination{})
	require.NoError(t, err)
	require.Equal(t, int64(1), total)
	err = env.OrgService.AcceptInvitation(ctx, invs[0].ID, memberID)
	require.NoError(t, err)

	// 2. Verify default team was created
	teams, count, err := env.OrgService.ListTeams(ctx, createdOrg.ID, ownerID, orgmodels.Pagination{})
	require.NoError(t, err)
	require.Equal(t, int64(1), count)
	require.Equal(t, "Engineering Corp", teams[0].Name)
	defaultTeamID := teams[0].ID

	// 3. Create second team
	team2, err := env.OrgService.CreateTeam(ctx, orgdtos.CreateTeamInput{
		OrganizationID: createdOrg.ID,
		Name:           "Core Team",
	}, ownerID)
	require.NoError(t, err)
	require.Equal(t, "Core Team", team2.Name)

	// Outsider cannot create team
	_, err = env.OrgService.CreateTeam(ctx, orgdtos.CreateTeamInput{
		OrganizationID: createdOrg.ID,
		Name:           "Hackers",
	}, outsiderID)
	require.Error(t, err)

	// 4. Update team
	updatedTeam, err := env.OrgService.UpdateTeam(ctx, orgdtos.UpdateTeamInput{
		TeamID: team2.ID,
		Name:   "Infrastructure Team",
	}, ownerID)
	require.NoError(t, err)
	require.Equal(t, "Infrastructure Team", updatedTeam.Name)

	// 5. Add team member
	tm, err := env.OrgService.AddTeamMember(ctx, orgdtos.AddTeamMemberInput{
		TeamID: team2.ID,
		UserID: memberID,
	}, ownerID)
	require.NoError(t, err)
	require.Equal(t, memberID, tm.UserID)

	// Outsider cannot be added to team (not in org)
	_, err = env.OrgService.AddTeamMember(ctx, orgdtos.AddTeamMemberInput{
		TeamID: team2.ID,
		UserID: outsiderID,
	}, ownerID)
	require.Error(t, err)

	// 6. List team members
	members, mCount, err := env.OrgService.ListTeamMembers(ctx, team2.ID, memberID, orgmodels.Pagination{})
	require.NoError(t, err)
	require.Equal(t, int64(1), mCount)
	require.Equal(t, memberID, members[0].UserID)

	// 7. MaximumMembersPerTeam enforcement
	// Add owner as second member -> succeeds
	_, err = env.OrgService.AddTeamMember(ctx, orgdtos.AddTeamMemberInput{
		TeamID: team2.ID,
		UserID: ownerID,
	}, ownerID)
	require.NoError(t, err)

	// Create 3rd org member to attempt exceeding team limit
	member3ID, _ := setupOrgUser(t, env, "member3@example.com", "", "")
	_, _ = env.OrgService.InviteMember(ctx, ownerID, orgdtos.InviteMemberInput{
		OrganizationID: createdOrg.ID,
		Email:          "member3@example.com",
		Role:           "member",
	})
	invs3, _, _ := env.OrgService.ListInvitations(ctx, createdOrg.ID, orgmodels.Pagination{})
	for _, inv := range invs3 {
		if inv.Email == "member3@example.com" {
			_ = env.OrgService.AcceptInvitation(ctx, inv.ID, member3ID)
		}
	}
	// 3rd member addition should fail because MaximumMembersPerTeam = 2
	_, err = env.OrgService.AddTeamMember(ctx, orgdtos.AddTeamMemberInput{
		TeamID: team2.ID,
		UserID: member3ID,
	}, ownerID)
	require.Error(t, err)

	// 8. MaximumTeams enforcement
	// Already 2 teams. Adding 1 more reaches max 3
	team3, err := env.OrgService.CreateTeam(ctx, orgdtos.CreateTeamInput{
		OrganizationID: createdOrg.ID,
		Name:           "QA Team",
	}, ownerID)
	require.NoError(t, err)

	// 4th team should fail
	_, err = env.OrgService.CreateTeam(ctx, orgdtos.CreateTeamInput{
		OrganizationID: createdOrg.ID,
		Name:           "Overflow Team",
	}, ownerID)
	require.Error(t, err)

	// 9. SetActiveTeam
	userModel := &coremodels.User{
		UserDto: coremodels.UserDto{
			FirstName: "Test",
			LastName:  "User",
			Email:     "active-team-test@example.com",
			Role:      enums.User,
		},
	}
	userModel.ID = memberID
	swu, err := env.Auth.Sessions().Create(ctx, userModel, serv_interfaces.SessionMeta{}, serv_interfaces.SessionCreateOptions{})
	require.NoError(t, err)

	updatedSess, err := env.OrgService.SetActiveTeam(ctx, swu.Session.ID, &team2.ID, memberID)
	require.NoError(t, err)
	require.NotNil(t, updatedSess.Session.ActiveTeamID)
	require.Equal(t, team2.ID, *updatedSess.Session.ActiveTeamID)

	// 10. RemoveTeamMember
	err = env.OrgService.RemoveTeamMember(ctx, orgdtos.RemoveTeamMemberInput{
		TeamID: team2.ID,
		UserID: memberID,
	}, memberID) // self removal
	require.NoError(t, err)

	// 11. DeleteTeam
	err = env.OrgService.DeleteTeam(ctx, orgdtos.DeleteTeamInput{TeamID: team3.ID}, ownerID)
	require.NoError(t, err)
	err = env.OrgService.DeleteTeam(ctx, orgdtos.DeleteTeamInput{TeamID: team2.ID}, ownerID)
	require.NoError(t, err)

	// AllowRemovingAllTeams is false, so deleting defaultTeam (the last team) must fail
	err = env.OrgService.DeleteTeam(ctx, orgdtos.DeleteTeamInput{TeamID: defaultTeamID}, ownerID)
	require.Error(t, err)
}

func TestOrgDynamicAccessControl(t *testing.T) {
	env, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		DynamicAccessControl: &orgconfig.DynamicAccessControlConfig{Enabled: true},
	})

	ctx := context.Background()
	ownerID, _ := setupOrgUser(t, env, "dac-owner@example.com", "", "")

	createdOrg, err := env.OrgService.CreateOrganization(ctx, ownerID, orgdtos.CreateOrgInput{
		Name: "Security Corp",
		Slug: "security-corp",
	})
	require.NoError(t, err)

	// 1. Create custom dynamic role
	permJSON := `{"project": ["create", "read"], "billing": ["read"]}`
	role, err := env.OrgService.CreateRole(ctx, createdOrg.ID, "project-manager", permJSON, ownerID)
	require.NoError(t, err)
	require.Equal(t, "project-manager", role.Role)

	// 2. Evaluate permissions
	// Allowed: project create
	ok, err := env.OrgService.HasPermission(ctx, createdOrg.ID, "project-manager", "project", "create")
	require.NoError(t, err)
	require.True(t, ok)

	// Allowed: billing read
	ok, err = env.OrgService.HasPermission(ctx, createdOrg.ID, "project-manager", "billing", "read")
	require.NoError(t, err)
	require.True(t, ok)

	// Denied: billing delete
	ok, err = env.OrgService.HasPermission(ctx, createdOrg.ID, "project-manager", "billing", "delete")
	require.NoError(t, err)
	require.False(t, ok)

	// Denied: unknown resource
	ok, err = env.OrgService.HasPermission(ctx, createdOrg.ID, "project-manager", "servers", "read")
	require.NoError(t, err)
	require.False(t, ok)

	// 3. Update role
	newPermJSON := `{"project": ["*"], "billing": ["read", "update"]}`
	updatedRole, err := env.OrgService.UpdateRole(ctx, createdOrg.ID, "project-manager", newPermJSON, ownerID)
	require.NoError(t, err)
	require.Equal(t, newPermJSON, updatedRole.Permission)

	// Now project delete should be allowed via wildcard
	ok, err = env.OrgService.HasPermission(ctx, createdOrg.ID, "project-manager", "project", "delete")
	require.NoError(t, err)
	require.True(t, ok)

	// 4. List roles
	roles, err := env.OrgService.ListRoles(ctx, createdOrg.ID, ownerID)
	require.NoError(t, err)
	require.Len(t, roles, 1)

	// 5. Delete role
	err = env.OrgService.DeleteRole(ctx, createdOrg.ID, "project-manager", ownerID)
	require.NoError(t, err)

	roles, err = env.OrgService.ListRoles(ctx, createdOrg.ID, ownerID)
	require.NoError(t, err)
	require.Empty(t, roles)
}

func TestOrgTeams_HandlerFlow(t *testing.T) {
	allowRemoveAll := true
	defaultTeam := false
	env, _ := setupTeamsEnv(t, orgconfig.OrgConfig{
		Teams: &orgconfig.TeamsConfig{
			Enabled:               true,
			DefaultTeam:           &defaultTeam,
			AllowRemovingAllTeams: allowRemoveAll,
		},
	})

	ctx := context.Background()
	ownerID, ownerAuthMap := setupOrgUser(t, env, "h-owner@example.com", "", "")
	memberID, memberAuthMap := setupOrgUser(t, env, "h-member@example.com", "", "")

	ownerAuth := humatypes.AuthHeaders{Authorization: ownerAuthMap["Authorization"]}
	memberAuth := humatypes.AuthHeaders{Authorization: memberAuthMap["Authorization"]}

	// Create org
	createdOrg, err := env.OrgService.CreateOrganization(ctx, ownerID, orgdtos.CreateOrgInput{
		Name: "Handler Teams Org",
		Slug: "handler-teams-org",
	})
	require.NoError(t, err)

	// Add member to org
	_, err = env.OrgService.InviteMember(ctx, ownerID, orgdtos.InviteMemberInput{
		OrganizationID: createdOrg.ID,
		Email:          "h-member@example.com",
		Role:           "member",
	})
	require.NoError(t, err)
	invs, _, _ := env.OrgService.ListInvitations(ctx, createdOrg.ID, orgmodels.Pagination{})
	err = env.OrgService.AcceptInvitation(ctx, invs[0].ID, memberID)
	require.NoError(t, err)

	// 1. Create team via handler
	createResp, err := env.OrgHandler.CreateTeam(ctx, &humaorg.CreateTeamInput{
		AuthHeaders: ownerAuth,
		Body: orgdtos.CreateTeamInput{
			OrganizationID: createdOrg.ID,
			Name:           "Devops",
		},
	})
	require.NoError(t, err)
	require.Equal(t, "Devops", createResp.Body.Name)
	teamID := createResp.Body.ID

	// 2. List teams via handler
	listResp, err := env.OrgHandler.ListTeams(ctx, &humaorg.ListTeamsInput{
		AuthHeaders:    memberAuth,
		OrganizationID: createdOrg.ID,
	})
	require.NoError(t, err)
	require.Len(t, listResp.Body, 1)

	// 3. Update team via handler
	updateResp, err := env.OrgHandler.UpdateTeam(ctx, &humaorg.UpdateTeamInput{
		AuthHeaders: ownerAuth,
		Body: orgdtos.UpdateTeamInput{
			TeamID:         teamID,
			Name:           "SRE & DevOps",
			OrganizationID: createdOrg.ID,
		},
	})
	require.NoError(t, err)
	require.Equal(t, "SRE & DevOps", updateResp.Body.Name)

	// 4. Add member via handler
	addResp, err := env.OrgHandler.AddTeamMember(ctx, &humaorg.AddTeamMemberInput{
		AuthHeaders: ownerAuth,
		Body: orgdtos.AddTeamMemberInput{
			TeamID:         teamID,
			UserID:         memberID,
			OrganizationID: createdOrg.ID,
		},
	})
	require.NoError(t, err)
	require.Equal(t, memberID, addResp.Body.UserID)

	// 5. Set active team via handler
	setActiveResp, err := env.OrgHandler.SetActiveTeam(ctx, &humaorg.SetActiveTeamInput{
		AuthHeaders: memberAuth,
		Body: orgdtos.SetActiveTeamInput{
			TeamID: &teamID,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, setActiveResp.Body.Session.ActiveTeamID)
	require.Equal(t, teamID, *setActiveResp.Body.Session.ActiveTeamID)

	// 6. Remove member via handler
	_, err = env.OrgHandler.RemoveTeamMember(ctx, &humaorg.RemoveTeamMemberInput{
		AuthHeaders: ownerAuth,
		Body: orgdtos.RemoveTeamMemberInput{
			TeamID:         teamID,
			UserID:         memberID,
			OrganizationID: createdOrg.ID,
		},
	})
	require.NoError(t, err)

	// 7. Delete team via handler
	_, err = env.OrgHandler.DeleteTeam(ctx, &humaorg.DeleteTeamInput{
		AuthHeaders: ownerAuth,
		Body: orgdtos.DeleteTeamInput{
			TeamID:         teamID,
			OrganizationID: createdOrg.ID,
		},
	})
	require.NoError(t, err)
}
