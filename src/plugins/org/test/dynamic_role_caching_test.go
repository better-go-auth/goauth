package org_test

import (
	"context"
	"testing"
	"time"

	coremodels "github.com/better-go-auth/goauth/src/models"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
	pluginrepos "github.com/better-go-auth/goauth/src/plugins/org/repository"
	orgrepo "github.com/better-go-auth/goauth/src/plugins/org/repository/gorm"
	orgsvc "github.com/better-go-auth/goauth/src/plugins/org/services"
	memorysec "github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestDynamicRole_CachingAndOperations tests dynamic role caching (Phase 6), operations evaluation, and cache invalidation.
func TestDynamicRole_CachingAndOperations(t *testing.T) {
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
				Email: "owner-cache-" + string(dbType) + "-" + uuid.New().String()[:8] + "@example.com",
			},
		}
		require.NoError(t, db.Create(owner).Error)

		orgID := uuid.New().String()
		testOrg := &orgmodels.Organization{
			Base:      coremodels.Base{ID: orgID, CreatedAt: now, UpdatedAt: now},
			Name:      "Acme Corp " + string(dbType),
			Slug:      "acme-cache-" + string(dbType) + "-" + uuid.New().String()[:8],
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

		secStore, err := memorysec.NewSecondaryStorage()
		require.NoError(t, err)

		cfg := orgconfig.OrgConfig{
			DynamicAccessControl: &orgconfig.DynamicAccessControlConfig{
				Enabled:    true,
				AuthMethod: orgconfig.AuthMethodBoth,
				CacheTTL:   10 * time.Minute,
				L1CacheTTL: 1 * time.Minute,
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
			ITeamRepo:             orgrepo.NewTeamRepo(db),
			ITeamMemberRepo:       orgrepo.NewTeamMemberRepo(db),
			IOrganizationRoleRepo: orgrepo.NewOrganizationRoleRepo(db),
		})
		svc.SetSecondaryStorage(secStore)

		ctx := context.Background()

		// Step 1: Create a role with both Permission and Ops
		perm := orgmodels.Permission{"repo": []string{"read", "write"}}
		ops := orgmodels.Operations{"cloneRepo", "pushCommit"}

		role, err := svc.CreateRoleWithOps(ctx, orgID, "developer", perm, ops, ownerID)
		require.NoError(t, err)
		require.Equal(t, "developer", role.Role)
		require.Equal(t, ops, role.Ops)

		// Step 2: Verify HasPermission and HasOperation work
		hasPerm, err := svc.HasPermission(ctx, orgID, "developer", "repo", "read")
		require.NoError(t, err)
		require.True(t, hasPerm)

		hasOp, err := svc.HasOperation(ctx, orgID, "developer", "cloneRepo")
		require.NoError(t, err)
		require.True(t, hasOp)

		hasOpDenied, err := svc.HasOperation(ctx, orgID, "developer", "deleteRepo")
		require.NoError(t, err)
		require.False(t, hasOpDenied)

		// Step 3: Verify roles are now cached in secondary storage
		cacheKey := "goauth:org:" + orgID + ":roles"
		cachedVal, exists, err := secStore.Get(ctx, cacheKey)
		require.NoError(t, err)
		require.True(t, exists)
		require.NotNil(t, cachedVal)

		// Step 4: Verify AuthorizeRole with different methods
		// Permission check
		authzPerm, err := svc.AuthorizeRole(ctx, orgID, "developer", orgsvc.AuthCheck{
			Resource: "repo",
			Action:   "write",
			Method:   orgconfig.AuthMethodPermission,
		})
		require.NoError(t, err)
		require.True(t, authzPerm)

		// Ops check
		authzOp, err := svc.AuthorizeRole(ctx, orgID, "developer", orgsvc.AuthCheck{
			OperationID: "pushCommit",
			Method:      orgconfig.AuthMethodOperations,
		})
		require.NoError(t, err)
		require.True(t, authzOp)

		// Both check
		authzBoth, err := svc.AuthorizeRole(ctx, orgID, "developer", orgsvc.AuthCheck{
			OperationID: "nonExistentOp",
			Resource:    "repo",
			Action:      "read",
			Method:      orgconfig.AuthMethodBoth,
		})
		require.NoError(t, err)
		require.True(t, authzBoth, "grants access when permission matches even if op does not")

		// Step 5: Update role with new ops and verify cache invalidation
		updatedOps := orgmodels.Operations{"cloneRepo", "pushCommit", "deleteRepo"}
		updatedRole, err := svc.UpdateRoleWithOps(ctx, orgID, "developer", perm, updatedOps, ownerID)
		require.NoError(t, err)
		require.Equal(t, updatedOps, updatedRole.Ops)

		// The updated op should now immediately succeed
		hasOpUpdated, err := svc.HasOperation(ctx, orgID, "developer", "deleteRepo")
		require.NoError(t, err)
		require.True(t, hasOpUpdated)

		// Step 6: Delete role and verify cache invalidation
		err = svc.DeleteRole(ctx, orgID, "developer", ownerID)
		require.NoError(t, err)

		hasOpAfterDelete, err := svc.HasOperation(ctx, orgID, "developer", "cloneRepo")
		require.NoError(t, err)
		require.False(t, hasOpAfterDelete)
	})
}
