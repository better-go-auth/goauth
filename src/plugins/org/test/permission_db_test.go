package org_test

import (
	"context"
	"database/sql/driver"
	"testing"

	coremodels "github.com/better-go-auth/goauth/src/models"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
	pluginrepos "github.com/better-go-auth/goauth/src/plugins/org/repository"
	orgrepo "github.com/better-go-auth/goauth/src/plugins/org/repository/gorm"
	orgsvc "github.com/better-go-auth/goauth/src/plugins/org/services"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestPermission_DatabaseOperations verifies Permission persistence, serializer tags,
// raw SQL column values, and updates across SQLite, PostgreSQL, and MySQL.
func TestPermission_DatabaseOperations(t *testing.T) {
	helpers.RunForEachDB(t, func(t *testing.T, db *gorm.DB, dbType helpers.DatabaseType) {
		// Step 1: Run core & org migrations on the database
		helpers.RunMigrations(t, db)

		// Step 2: Insert parent Organization and OrganizationRole with Permission
		orgID := uuid.New().String()
		roleID := uuid.New().String()
		now := coremodels.TimeNow()

		parentOrg := &orgmodels.Organization{
			Base: coremodels.Base{ID: orgID, CreatedAt: now, UpdatedAt: now},
			Name: "Test Org " + string(dbType),
			Slug: "test-org-" + string(dbType) + "-" + uuid.New().String()[:8],
		}
		require.NoError(t, db.Create(parentOrg).Error)

		role := &orgmodels.OrganizationRole{
			Base:           coremodels.Base{ID: roleID, CreatedAt: now, UpdatedAt: now},
			OrganizationID: orgID,
			Role:           "devops",
			Permission: orgmodels.Permission{
				"infra":     []string{"read", "deploy", "restart"},
				"databases": []string{"backup", "read"},
			},
		}
		err := db.Create(role).Error
		require.NoError(t, err)

		// Step 3: Query back via GORM and verify deserialization into Permission
		var loaded orgmodels.OrganizationRole
		err = db.Where("id = ?", roleID).Take(&loaded).Error
		require.NoError(t, err)
		require.Equal(t, "devops", loaded.Role)
		require.Equal(t, []string{"read", "deploy", "restart"}, loaded.Permission["infra"])
		require.True(t, loaded.Permission.HasAction("infra", "deploy"))
		require.False(t, loaded.Permission.HasAction("infra", "destroy"))

		// Step 4: Verify raw database column text in the DB engine
		var rawJSON string
		err = db.Raw("SELECT permission FROM organization_roles WHERE id = ?", roleID).Scan(&rawJSON).Error
		require.NoError(t, err)
		require.JSONEq(t, `{"infra":["read","deploy","restart"],"databases":["backup","read"]}`, rawJSON)

		// Step 5: Update via OrganizationRoleRepo
		roleRepo := orgrepo.NewOrganizationRoleRepo(db)
		newPerm := orgmodels.Permission{
			"*":     []string{"read"},
			"infra": []string{"*"},
		}
		updated, err := roleRepo.UpdateRole(context.Background(), orgID, "devops", newPerm)
		require.NoError(t, err)
		require.Equal(t, newPerm, updated.Permission)
		require.True(t, updated.Permission.HasAction("infra", "destroy"))
		require.True(t, updated.Permission.HasAction("monitoring", "read"))
		require.False(t, updated.Permission.HasAction("monitoring", "write"))

		// Step 6: Verify updated raw database text
		err = db.Raw("SELECT permission FROM organization_roles WHERE id = ?", roleID).Scan(&rawJSON).Error
		require.NoError(t, err)
		require.JSONEq(t, `{"*":["read"],"infra":["*"]}`, rawJSON)

		// Step 7: Verify driver.Valuer interface is directly tested
		var driverVal driver.Valuer = updated.Permission
		val, err := driverVal.Value()
		require.NoError(t, err)
		require.JSONEq(t, `{"*":["read"],"infra":["*"]}`, val.(string))
	})
}

// TestPermission_OrgServiceEndToEnd tests OrgService dynamic access control operations with Permission
// across SQLite, PostgreSQL, and MySQL.
func TestPermission_OrgServiceEndToEnd(t *testing.T) {
	helpers.RunForEachDB(t, func(t *testing.T, db *gorm.DB, dbType helpers.DatabaseType) {
		// Step 1: Migrate tables for the database engine
		helpers.RunMigrations(t, db)

		// Step 2: Seed Owner User and Organization
		ownerID := uuid.New().String()
		now := coremodels.TimeNow()
		owner := &coremodels.User{
			Base: coremodels.Base{ID: ownerID, CreatedAt: now, UpdatedAt: now},
			UserDto: coremodels.UserDto{
				Name:  "Test Owner",
				Email: "owner-" + string(dbType) + "-" + uuid.New().String()[:8] + "@example.com",
			},
		}
		require.NoError(t, db.Create(owner).Error)

		orgID := uuid.New().String()
		testOrg := &orgmodels.Organization{
			Base:      coremodels.Base{ID: orgID, CreatedAt: now, UpdatedAt: now},
			Name:      "Acme Corp " + string(dbType),
			Slug:      "acme-" + string(dbType) + "-" + uuid.New().String()[:8],
			CreatedBy: ownerID,
		}
		require.NoError(t, db.Create(testOrg).Error)

		member := &orgmodels.Member{
			Base:           coremodels.Base{ID: uuid.New().String(), CreatedAt: now, UpdatedAt: now},
			OrganizationID: orgID,
			UserID:         ownerID,
			Role:           orgmodels.OrgRoleOwner,
		}
		require.NoError(t, db.Create(member).Error)

		// Step 3: Initialize OrgService with Dynamic Access Control enabled
		cfg := orgconfig.OrgConfig{
			DynamicAccessControl: &orgconfig.DynamicAccessControlConfig{
				Enabled: true,
			},
		}
		svc := orgsvc.New(
			orgrepo.NewOrgRepo(db),
			orgrepo.NewMemberRepo(db),
			orgrepo.NewInvitationRepo(db),
			nil,
			nil,
			nil,
		)
		svc.Config = cfg
		svc.SetRepositories(pluginrepos.OrgRepositories{
			IOrganizationRoleRepo: orgrepo.NewOrganizationRoleRepo(db),
		})

		ctx := context.Background()

		// Step 4: Create dynamic role passing models.Permission
		perm := orgmodels.Permission{
			"billing":  []string{"view", "download-invoice"},
			"projects": []string{"create", "read"},
		}
		createdRole, err := svc.CreateRole(ctx, orgID, "accountant", perm, ownerID)
		require.NoError(t, err)
		require.Equal(t, "accountant", createdRole.Role)
		require.Equal(t, perm, createdRole.Permission)

		// Step 5: Evaluate permissions with HasPermission
		allowed, err := svc.HasPermission(ctx, orgID, "accountant", "billing", "view")
		require.NoError(t, err)
		require.True(t, allowed)

		allowed, err = svc.HasPermission(ctx, orgID, "accountant", "billing", "delete")
		require.NoError(t, err)
		require.False(t, allowed)

		// Step 6: Create another role using parsed JSON string input
		jsonPerm, err := orgmodels.ParsePermission(`{"analytics": ["view", "export"]}`)
		require.NoError(t, err)
		analystRole, err := svc.CreateRole(ctx, orgID, "analyst", jsonPerm, ownerID)
		require.NoError(t, err)
		require.Equal(t, []string{"view", "export"}, analystRole.Permission["analytics"])

		allowed, err = svc.HasPermission(ctx, orgID, "analyst", "analytics", "export")
		require.NoError(t, err)
		require.True(t, allowed)

		// Step 7: Update role permission to wildcard
		updatedRole, err := svc.UpdateRole(ctx, orgID, "accountant", orgmodels.Permission{"billing": []string{"*"}}, ownerID)
		require.NoError(t, err)
		require.Equal(t, []string{"*"}, updatedRole.Permission["billing"])

		allowed, err = svc.HasPermission(ctx, orgID, "accountant", "billing", "delete")
		require.NoError(t, err)
		require.True(t, allowed)

		// Step 8: List and Delete roles
		roles, err := svc.ListRoles(ctx, orgID, ownerID)
		require.NoError(t, err)
		require.Len(t, roles, 2)

		err = svc.DeleteRole(ctx, orgID, "accountant", ownerID)
		require.NoError(t, err)

		roles, err = svc.ListRoles(ctx, orgID, ownerID)
		require.NoError(t, err)
		require.Len(t, roles, 1)
	})
}
