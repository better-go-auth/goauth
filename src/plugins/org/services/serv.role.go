package orgsvc

import (
	"context"
	"fmt"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	coremodels "github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
	orgerrors "github.com/better-go-auth/goauth/src/plugins/org/org-errors"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
)

// ─── Dynamic Access Control Operations ─────────────────────────────────────────

func (s *OrgService) CreateRole(ctx context.Context, orgID, role string, permission models.Permission, requestingUserID string) (*models.OrganizationRole, error) {
	return s.CreateRoleWithOps(ctx, orgID, role, permission, nil, requestingUserID)
}

func (s *OrgService) CreateRoleWithOps(ctx context.Context, orgID, role string, permission models.Permission, ops models.Operations, requestingUserID string) (*models.OrganizationRole, error) {
	// Step 1: Verify dynamic access control is enabled in org config
	if !s.DynamicAccessControlEnabled() {
		return nil, autherr.ErrForbidden
	}
	// Step 2: Validate requester is organization owner
	requester, err := s.memberRepo.GetMemberByOrgAndUser(ctx, orgID, requestingUserID)
	if err != nil || requester == nil || requester.Role != models.OrgRoleOwner {
		return nil, autherr.ErrForbidden
	}

	// Step 3: Check maximum roles per organization limit if configured
	if s.Config.DynamicAccessControl != nil {
		if s.Config.DynamicAccessControl.MaximumRolesPerOrganization != nil {
			roles, err := s.orgRoleRepo.ListRolesByOrgID(ctx, orgID)
			if err == nil && len(roles) >= *s.Config.DynamicAccessControl.MaximumRolesPerOrganization {
				return nil, orgerrors.ErrMaximumRolesReached
			}
		}
		if s.Config.DynamicAccessControl.MaximumRolesPerOrganizationFn != nil {
			maxRoles, err := s.Config.DynamicAccessControl.MaximumRolesPerOrganizationFn(ctx, orgID)
			if err != nil {
				return nil, err
			}
			if maxRoles > 0 {
				roles, err := s.orgRoleRepo.ListRolesByOrgID(ctx, orgID)
				if err == nil && len(roles) >= maxRoles {
					return nil, orgerrors.ErrMaximumRolesReached
				}
			}
		}
	}

	// Step 4: Ensure non-nil permission map to prevent nil map panics
	if permission == nil {
		permission = make(models.Permission)
	}

	// Step 5: Ensure non-nil operations slice
	if ops == nil {
		ops = make(models.Operations, 0)
	}

	// Step 6: Construct OrganizationRole model
	now := coremodels.TimeNow()
	r := &models.OrganizationRole{
		Base:           coremodels.Base{ID: coremodels.NewID(), CreatedAt: now, UpdatedAt: now},
		OrganizationID: orgID,
		Role:           role,
		Permission:     permission,
		Ops:            ops,
	}

	// Step 7: Persist role to repository
	created, err := s.orgRoleRepo.CreateRole(ctx, r)
	if err != nil {
		return nil, err
	}

	// Step 8: Invalidate cached roles for this organization
	s.invalidateRoleCache(ctx, orgID)
	return created, nil
}

func (s *OrgService) GetRole(ctx context.Context, orgID, role, requestingUserID string) (*models.OrganizationRole, error) {
	requester, err := s.memberRepo.GetMemberByOrgAndUser(ctx, orgID, requestingUserID)
	if err != nil || requester == nil {
		return nil, autherr.ErrForbidden
	}
	r, err := s.orgRoleRepo.GetRole(ctx, orgID, role)
	if err != nil || r == nil {
		return nil, orgerrors.ErrOrgRoleNotFound
	}
	return r, nil
}

func (s *OrgService) UpdateRole(ctx context.Context, orgID, role string, permission models.Permission, requestingUserID string) (*models.OrganizationRole, error) {
	return s.UpdateRoleWithOps(ctx, orgID, role, permission, nil, requestingUserID)
}

func (s *OrgService) UpdateRoleWithOps(ctx context.Context, orgID, role string, permission models.Permission, ops models.Operations, requestingUserID string) (*models.OrganizationRole, error) {
	// Step 1: Verify dynamic access control is enabled in org config
	if !s.DynamicAccessControlEnabled() {
		return nil, autherr.ErrForbidden
	}
	// Step 2: Validate requester is organization owner
	requester, err := s.memberRepo.GetMemberByOrgAndUser(ctx, orgID, requestingUserID)
	if err != nil || requester == nil || requester.Role != models.OrgRoleOwner {
		return nil, autherr.ErrForbidden
	}
	// Step 3: Ensure non-nil permission map
	if permission == nil {
		permission = make(models.Permission)
	}

	// Step 4: Persist updated role in repository
	var updated *models.OrganizationRole
	if ops != nil {
		updated, err = s.orgRoleRepo.UpdateRoleWithOps(ctx, orgID, role, permission, ops)
	} else {
		updated, err = s.orgRoleRepo.UpdateRole(ctx, orgID, role, permission)
	}
	if err != nil {
		return nil, err
	}

	// Step 5: Invalidate cached roles for this organization
	s.invalidateRoleCache(ctx, orgID)
	return updated, nil
}

func (s *OrgService) DeleteRole(ctx context.Context, orgID, role, requestingUserID string) error {
	if !s.DynamicAccessControlEnabled() {
		return autherr.ErrForbidden
	}
	requester, err := s.memberRepo.GetMemberByOrgAndUser(ctx, orgID, requestingUserID)
	if err != nil || requester == nil || requester.Role != models.OrgRoleOwner {
		return autherr.ErrForbidden
	}
	if err := s.orgRoleRepo.DeleteRole(ctx, orgID, role); err != nil {
		return err
	}
	// Invalidate cached roles for this organization
	s.invalidateRoleCache(ctx, orgID)
	return nil
}

func (s *OrgService) ListRoles(ctx context.Context, orgID, requestingUserID string) ([]models.OrganizationRole, error) {
	requester, err := s.memberRepo.GetMemberByOrgAndUser(ctx, orgID, requestingUserID)
	if err != nil || requester == nil {
		return nil, autherr.ErrForbidden
	}
	return s.orgRoleRepo.ListRolesByOrgID(ctx, orgID)
}

func (s *OrgService) HasPermission(ctx context.Context, orgID, role, resource, action string) (bool, error) {
	// Step 1: Owner always bypasses and has full access
	if role == string(models.OrgRoleOwner) {
		return true, nil
	}

	// Step 2: If dynamic access control is disabled, check custom static roles or built-in static roles
	if !s.DynamicAccessControlEnabled() {
		// Check custom static roles configured on plugin
		if s.Config.Roles != nil {
			if perm, ok := s.Config.Roles[role]; ok {
				return perm.HasAction(resource, action), nil
			}
		}

		if role == string(models.OrgRoleAdmin) {
			if resource == "organization" && (action == "delete" || action == "update-role") {
				return false, nil
			}
			return true, nil
		}
		if role == models.OrgRoleMember.Str() {
			return action == "read" || action == "list" || action == "get", nil
		}
		return false, nil
	}

	// Step 3: Fetch cached role definitions for the organization (L1/L2)
	rolesMap, err := s.getOrgRolesCached(ctx, orgID)
	if err != nil {
		// Fallback to direct DB lookup on cache failure
		if s.orgRoleRepo != nil {
			r, dbErr := s.orgRoleRepo.GetRole(ctx, orgID, role)
			if dbErr == nil && r != nil {
				return r.Permission.HasAction(resource, action), nil
			}
		}
		return false, err
	}

	// Step 4: Check permission directly on matched role
	r, exists := rolesMap[role]
	if !exists || r == nil {
		return false, nil
	}
	return r.Permission.HasAction(resource, action), nil
}

func (s *OrgService) HasOperation(ctx context.Context, orgID, role, operationID string) (bool, error) {
	// Step 1: Owner always bypasses and has full operation access
	if role == string(models.OrgRoleOwner) {
		return true, nil
	}

	// Step 2: If dynamic access control is disabled, evaluate built-in admin/member fallback
	if !s.DynamicAccessControlEnabled() {
		if role == string(models.OrgRoleAdmin) {
			return operationID != "deleteOrganization", nil
		}
		return false, nil
	}

	// Step 3: Fetch cached role definitions for the organization (L1/L2)
	rolesMap, err := s.getOrgRolesCached(ctx, orgID)
	if err != nil {
		// Fallback to direct DB lookup on cache failure
		if s.orgRoleRepo != nil {
			r, dbErr := s.orgRoleRepo.GetRole(ctx, orgID, role)
			if dbErr == nil && r != nil {
				return r.Ops.HasOp(operationID), nil
			}
		}
		return false, err
	}

	// Step 4: Check operation directly on matched role's Ops
	r, exists := rolesMap[role]
	if !exists || r == nil {
		return false, nil
	}
	return r.Ops.HasOp(operationID), nil
}

func (s *OrgService) AuthorizeRole(ctx context.Context, orgID, role string, check AuthCheck) (bool, error) {
	// Step 1: Owner always has full access
	if role == string(models.OrgRoleOwner) {
		return true, nil
	}

	// Step 2: Determine effective auth method
	var method orgconfig.AuthMethod
	if s.Config.DynamicAccessControl != nil {
		method = s.Config.DynamicAccessControl.AuthMethod
	}
	if check.Method != "" {
		method = check.Method
	}
	if method == "" {
		method = orgconfig.AuthMethodPermission
	}

	// Step 3: Evaluate based on configured method
	switch method {
	case orgconfig.AuthMethodOperations:
		if check.OperationID == "" {
			return false, fmt.Errorf("orgsvc: operationId is required for AuthMethodOperations")
		}
		return s.HasOperation(ctx, orgID, role, check.OperationID)

	case orgconfig.AuthMethodBoth:
		var hasOp, hasPerm bool
		if check.OperationID != "" {
			allowed, err := s.HasOperation(ctx, orgID, role, check.OperationID)
			if err != nil {
				return false, err
			}
			hasOp = allowed
		}
		if check.Resource != "" && check.Action != "" {
			allowed, err := s.HasPermission(ctx, orgID, role, check.Resource, check.Action)
			if err != nil {
				return false, err
			}
			hasPerm = allowed
		}
		return hasOp || hasPerm, nil

	default: // AuthMethodPermission
		if check.Resource == "" || check.Action == "" {
			if check.OperationID != "" {
				return s.HasOperation(ctx, orgID, role, check.OperationID)
			}
			return false, fmt.Errorf("orgsvc: resource and action are required for AuthMethodPermission")
		}
		return s.HasPermission(ctx, orgID, role, check.Resource, check.Action)
	}
}
