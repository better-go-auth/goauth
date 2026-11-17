package orgsvc

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	coremodels "github.com/better-go-auth/goauth/src/models"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
	orgerrors "github.com/better-go-auth/goauth/src/plugins/org/org-errors"
	"github.com/better-go-auth/goauth/src/providers/access"
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
	if orgID == "" {
		return nil, orgerrors.ErrMustBeInOrgToCreateRole
	}
	// Step 2: Normalize the role name (better-auth lowercases) and protect predefined role names
	role = normalizeRoleName(role)
	if role == "" {
		return nil, autherr.New(autherr.BadRequest, "role is required", http.StatusBadRequest)
	}
	if s.Config.IsPredefinedRole(role) {
		return nil, orgerrors.ErrRoleNameIsAlreadyTaken
	}
	// Step 3: Validate requester is a member holding ac:create (better-auth; owner/admin by default)
	requester, err := s.memberRepo.GetMemberByOrgAndUser(ctx, orgID, requestingUserID)
	if err != nil || requester == nil {
		return nil, orgerrors.ErrNotAMemberOfThisOrganization
	}
	if ok, err := s.HasPermissions(ctx, orgID, string(requester.Role), acRequest("create")); err != nil || !ok {
		return nil, orgerrors.ErrNotAllowedToCreateRole
	}

	// Step 4: Check maximum roles per organization limit if configured
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

	// Step 5: Ensure non-nil permission map to prevent nil map panics
	if permission == nil {
		permission = make(models.Permission)
	}

	// Step 6: Reject unknown resources and privilege escalation (better-auth checkForInvalidResources /
	// checkIfMemberHasPermission): the requester must hold every permission granted to the new role
	if err := s.checkForInvalidResources(permission); err != nil {
		return nil, err
	}
	if err := s.checkIfMemberHasPermission(ctx, orgID, string(requester.Role), permission, orgerrors.ErrNotAllowedToCreateRole); err != nil {
		return nil, err
	}

	// Step 7: The name must not be taken by another dynamic role
	if existing, err := s.orgRoleRepo.GetRole(ctx, orgID, role); err == nil && existing != nil {
		return nil, orgerrors.ErrRoleNameIsAlreadyTaken
	}

	// Step 8: Ensure non-nil operations slice
	if ops == nil {
		ops = make(models.Operations, 0)
	}

	// Step 9: Construct OrganizationRole model
	now := coremodels.TimeNow()
	r := &models.OrganizationRole{
		Base:           coremodels.Base{ID: coremodels.NewID(), CreatedAt: now, UpdatedAt: now},
		OrganizationID: orgID,
		Role:           role,
		Permission:     permission,
		Ops:            ops,
	}

	// Step 10: Persist role to repository
	created, err := s.orgRoleRepo.CreateRole(ctx, r)
	if err != nil {
		return nil, err
	}

	// Step 11: Invalidate cached roles for this organization
	s.invalidateRoleCache(ctx, orgID)
	return created, nil
}

func (s *OrgService) GetRole(ctx context.Context, orgID, role, requestingUserID string) (*models.OrganizationRole, error) {
	return s.GetRoleBy(ctx, orgID, role, "", requestingUserID)
}

// GetRoleBy mirrors better-auth GET /organization/get-role: lookup by roleName or roleId,
// requires membership and ac:read.
func (s *OrgService) GetRoleBy(ctx context.Context, orgID, roleName, roleID, requestingUserID string) (*models.OrganizationRole, error) {
	// Step 1: membership and ac:read
	if err := s.requireRolePermission(ctx, orgID, requestingUserID, "read", orgerrors.ErrNotAllowedToReadRole); err != nil {
		return nil, err
	}
	// Step 2: lookup
	return s.findRole(ctx, orgID, roleName, roleID)
}

func (s *OrgService) UpdateRole(ctx context.Context, orgID, role string, permission models.Permission, requestingUserID string) (*models.OrganizationRole, error) {
	return s.UpdateRoleWithOps(ctx, orgID, role, permission, nil, requestingUserID)
}

func (s *OrgService) UpdateRoleWithOps(ctx context.Context, orgID, role string, permission models.Permission, ops models.Operations, requestingUserID string) (*models.OrganizationRole, error) {
	// Step 1: Ensure non-nil permission map
	if permission == nil {
		permission = make(models.Permission)
	}
	// Step 2: Delegate to the better-auth flow (permission checks, escalation, cache invalidation)
	return s.UpdateRoleBy(ctx, orgID, role, "", UpdateRoleData{Permission: permission, Ops: ops}, requestingUserID)
}

// UpdateRoleData carries better-auth's update-role `data` (permission and/or roleName) plus goauth's Ops.
type UpdateRoleData struct {
	Permission models.Permission
	RoleName   string
	Ops        models.Operations
}

// UpdateRoleBy mirrors better-auth POST /organization/update-role.
func (s *OrgService) UpdateRoleBy(ctx context.Context, orgID, roleName, roleID string, data UpdateRoleData, requestingUserID string) (*models.OrganizationRole, error) {
	// Step 1: Verify dynamic access control is enabled in org config
	if !s.DynamicAccessControlEnabled() {
		return nil, autherr.ErrForbidden
	}
	// Step 2: Validate requester membership and ac:update
	requester, err := s.memberRepo.GetMemberByOrgAndUser(ctx, orgID, requestingUserID)
	if err != nil || requester == nil {
		return nil, orgerrors.ErrNotAMemberOfThisOrganization
	}
	if ok, err := s.HasPermissions(ctx, orgID, string(requester.Role), acRequest("update")); err != nil || !ok {
		return nil, orgerrors.ErrNotAllowedToUpdateRole
	}
	// Step 3: Find the role to update
	existing, err := s.findRole(ctx, orgID, roleName, roleID)
	if err != nil {
		return nil, err
	}
	// Step 4: New permission: no invalid resources, no privilege escalation
	if data.Permission != nil {
		if err := s.checkForInvalidResources(data.Permission); err != nil {
			return nil, err
		}
		if err := s.checkIfMemberHasPermission(ctx, orgID, string(requester.Role), data.Permission, orgerrors.ErrNotAllowedToUpdateRole); err != nil {
			return nil, err
		}
	}
	// Step 5: New name: normalized, not predefined, not taken
	newName := ""
	if data.RoleName != "" {
		newName = normalizeRoleName(data.RoleName)
		if s.Config.IsPredefinedRole(newName) {
			return nil, orgerrors.ErrRoleNameIsAlreadyTaken
		}
		if newName != existing.Role {
			if taken, err := s.orgRoleRepo.GetRole(ctx, orgID, newName); err == nil && taken != nil {
				return nil, orgerrors.ErrRoleNameIsAlreadyTaken
			}
		}
	}
	// Step 6: Persist updated permission / ops in repository
	var updated = existing
	if data.Permission != nil || data.Ops != nil {
		permission := data.Permission
		if permission == nil {
			permission = existing.Permission
		}
		if data.Ops != nil {
			updated, err = s.orgRoleRepo.UpdateRoleWithOps(ctx, orgID, existing.Role, permission, data.Ops)
		} else {
			updated, err = s.orgRoleRepo.UpdateRole(ctx, orgID, existing.Role, permission)
		}
		if err != nil {
			return nil, err
		}
	}
	// Step 7: Persist the rename
	if newName != "" && newName != existing.Role {
		if err := s.orgRoleRepo.RenameRole(ctx, orgID, existing.Role, newName); err != nil {
			return nil, err
		}
		if updated, err = s.orgRoleRepo.GetRole(ctx, orgID, newName); err != nil {
			return nil, err
		}
	}

	// Step 8: Invalidate cached roles for this organization
	s.invalidateRoleCache(ctx, orgID)
	return updated, nil
}

func (s *OrgService) DeleteRole(ctx context.Context, orgID, role, requestingUserID string) error {
	return s.DeleteRoleBy(ctx, orgID, role, "", requestingUserID)
}

// DeleteRoleBy mirrors better-auth POST /organization/delete-role.
func (s *OrgService) DeleteRoleBy(ctx context.Context, orgID, roleName, roleID, requestingUserID string) error {
	// Step 1: Verify dynamic access control is enabled in org config
	if !s.DynamicAccessControlEnabled() {
		return autherr.ErrForbidden
	}
	// Step 2: membership and ac:delete
	if err := s.requireRolePermission(ctx, orgID, requestingUserID, "delete", orgerrors.ErrNotAllowedToDeleteRole); err != nil {
		return err
	}
	// Step 3: predefined roles cannot be deleted
	if roleName != "" && s.Config.IsPredefinedRole(roleName) {
		return orgerrors.ErrCannotDeleteAPreDefinedRole
	}
	// Step 4: the role must exist
	existing, err := s.findRole(ctx, orgID, roleName, roleID)
	if err != nil {
		return err
	}
	// Step 5: refuse while members still hold the role (comma-separated roles included)
	assigned, err := s.roleIsAssigned(ctx, orgID, existing.Role)
	if err != nil {
		return err
	}
	if assigned {
		return orgerrors.ErrRoleIsAssignedToMembers
	}
	// Step 6: delete
	if err := s.orgRoleRepo.DeleteRole(ctx, orgID, existing.Role); err != nil {
		return err
	}
	// Invalidate cached roles for this organization
	s.invalidateRoleCache(ctx, orgID)
	return nil
}

func (s *OrgService) ListRoles(ctx context.Context, orgID, requestingUserID string) ([]models.OrganizationRole, error) {
	// Step 1: membership and ac:read (better-auth list-roles)
	if err := s.requireRolePermission(ctx, orgID, requestingUserID, "read", orgerrors.ErrNotAllowedToListRole); err != nil {
		return nil, err
	}
	// Step 2: list
	if s.orgRoleRepo == nil {
		return []models.OrganizationRole{}, nil
	}
	return s.orgRoleRepo.ListRolesByOrgID(ctx, orgID)
}

// requireRolePermission checks the requester is a member of orgID holding ac:<action>.
func (s *OrgService) requireRolePermission(ctx context.Context, orgID, userID, action string, denied *autherr.AuthError) error {
	requester, err := s.memberRepo.GetMemberByOrgAndUser(ctx, orgID, userID)
	if err != nil || requester == nil {
		return orgerrors.ErrNotAMemberOfThisOrganization
	}
	if ok, err := s.HasPermissions(ctx, orgID, string(requester.Role), acRequest(action)); err != nil || !ok {
		return denied
	}
	return nil
}

// findRole loads a dynamic role by name (or by id when roleName is empty).
func (s *OrgService) findRole(ctx context.Context, orgID, roleName, roleID string) (*models.OrganizationRole, error) {
	if s.orgRoleRepo == nil || (roleName == "" && roleID == "") {
		return nil, orgerrors.ErrOrgRoleNotFound
	}
	if roleName != "" {
		r, err := s.orgRoleRepo.GetRole(ctx, orgID, roleName)
		if err != nil || r == nil {
			return nil, orgerrors.ErrOrgRoleNotFound
		}
		return r, nil
	}
	roles, err := s.orgRoleRepo.ListRolesByOrgID(ctx, orgID)
	if err != nil {
		return nil, err
	}
	for i := range roles {
		if roles[i].ID == roleID {
			return &roles[i], nil
		}
	}
	return nil, orgerrors.ErrOrgRoleNotFound
}

// roleIsAssigned reports whether any member of orgID holds role (exact match within "a,b" strings).
func (s *OrgService) roleIsAssigned(ctx context.Context, orgID, role string) (bool, error) {
	const pageSize = 500
	for offset := 0; ; offset += pageSize {
		members, total, err := s.memberRepo.ListMembersByOrgID(ctx, orgID, models.Pagination{Limit: pageSize, Offset: offset})
		if err != nil {
			return false, err
		}
		for _, m := range members {
			for _, r := range access.SplitRoles(string(m.Role)) {
				if r == role {
					return true, nil
				}
			}
		}
		if len(members) == 0 || int64(offset+len(members)) >= total {
			return false, nil
		}
	}
}

// checkForInvalidResources mirrors better-auth: in better-auth mode every resource must be defined
// on the AccessControl. Legacy mode has no statement set, so any resource (and "*") is accepted.
func (s *OrgService) checkForInvalidResources(permission models.Permission) error {
	if !s.Config.BetterAuthMode() {
		return nil
	}
	if len(s.Config.EffectiveAC().InvalidResources(access.Statements(permission))) > 0 {
		return orgerrors.ErrInvalidResource
	}
	return nil
}

// checkIfMemberHasPermission mirrors better-auth: the requester's role must hold every
// resource:action it grants, so roles cannot be used to escalate privileges.
func (s *OrgService) checkIfMemberHasPermission(ctx context.Context, orgID, role string, permission models.Permission, denied *autherr.AuthError) error {
	var missing []string
	for _, resource := range access.Statements(permission).Resources() {
		for _, action := range permission[resource] {
			ok, err := s.HasPermissions(ctx, orgID, role, access.Req(map[string][]string{resource: {action}}))
			if err != nil {
				return err
			}
			if !ok {
				missing = append(missing, resource+":"+action)
			}
		}
	}
	if len(missing) > 0 {
		// better-auth also returns `missingPermissions` in the body; goauth's error shape has no
		// extra fields, so they are only logged
		slog.DebugContext(ctx, "orgsvc: role grants permissions the requester lacks", "missingPermissions", strings.Join(missing, ", "))
		return denied
	}
	return nil
}

// normalizeRoleName mirrors better-auth (role names are stored lowercase).
func normalizeRoleName(role string) string {
	return strings.ToLower(strings.TrimSpace(role))
}

// acRequest builds an {"ac": [action]} permission request.
func acRequest(action string) access.Request {
	return access.Req(map[string][]string{"ac": {action}})
}

// HasPermission checks a single resource/action for role (comma-separated roles supported).
// See HasPermissions for the better-auth / legacy semantics.
func (s *OrgService) HasPermission(ctx context.Context, orgID, role, resource, action string) (bool, error) {
	return s.HasPermissions(ctx, orgID, role, access.Req(map[string][]string{resource: {action}}))
}

// HasPermissions mirrors better-auth's organization hasPermission(): any of the comma-separated
// roles must authorize the whole request.
//
//   - better-auth mode (AccessControl/AccessRoles/BetterAuthPermissions configured): predefined roles are
//     Config.AccessRoles (or owner/admin/member defaults); with dynamic access control, DB roles are
//     MERGED into the predefined role of the same name. No owner bypass, no wildcards.
//   - legacy mode (default): owner bypasses everything; Config.Roles (with "*" wildcards) or the
//     built-in admin/member rules define predefined roles; DB roles are merged (OR) into them.
func (s *OrgService) HasPermissions(ctx context.Context, orgID, role string, request access.Request) (bool, error) {
	// Step 1: Nothing requested is never authorized
	if len(request) == 0 {
		return false, nil
	}
	// Step 2: Load dynamic roles (cached L1/L2) when dynamic access control is enabled
	var dbRoles map[string]*models.OrganizationRole
	if s.DynamicAccessControlEnabled() && s.orgRoleRepo != nil {
		rolesMap, err := s.getOrgRolesCached(ctx, orgID)
		if err != nil {
			// Fallback to direct DB lookup on cache failure
			rolesMap = make(map[string]*models.OrganizationRole)
			for _, name := range access.SplitRoles(role) {
				if r, dbErr := s.orgRoleRepo.GetRole(ctx, orgID, name); dbErr == nil && r != nil {
					rolesMap[name] = r
				}
			}
			if len(rolesMap) == 0 {
				return false, err
			}
		}
		dbRoles = rolesMap
	}

	// Step 3: better-auth semantics: merge DB statements into the predefined roles and authorize
	if s.Config.BetterAuthMode() {
		acRoles := s.Config.EffectiveRoles()
		for name, r := range dbRoles {
			if r == nil {
				continue
			}
			var base access.Statements
			if existing, ok := acRoles[name]; ok {
				base = existing.Statements()
			}
			acRoles[name] = s.Config.EffectiveAC().NewRole(base.Merge(access.Statements(r.Permission)))
		}
		return access.HasPermission(acRoles, role, request), nil
	}

	// Step 4: legacy semantics, evaluated per role with better-auth's authorize algorithm
	for _, name := range access.SplitRoles(role) {
		checker := legacyRole{name: name, cfg: s.Config}
		if r, ok := dbRoles[name]; ok && r != nil {
			checker.dynamic = r.Permission
		}
		if res, err := access.Evaluate(checker, request); err == nil && res.Success {
			return true, nil
		}
	}
	return false, nil
}

// legacyRole implements access.Checker with goauth's historical organization rules.
type legacyRole struct {
	name    string
	cfg     orgconfig.OrgConfig
	dynamic models.Permission // merged (OR) dynamic DB permission, may be nil
}

// static returns the Config.Roles permission for the role, if configured.
func (l legacyRole) static() (models.Permission, bool) {
	if l.cfg.Roles == nil {
		return nil, false
	}
	p, ok := l.cfg.Roles[l.name]
	return p, ok
}

func (l legacyRole) HasResource(resource string) bool {
	// Step 1: owner, and the built-in admin/member, know every resource
	if l.name == string(models.OrgRoleOwner) {
		return true
	}
	if p, ok := l.static(); ok {
		if _, has := p[resource]; has {
			return true
		}
		if _, has := p["*"]; has {
			return true
		}
	} else if l.name == string(models.OrgRoleAdmin) || l.name == models.OrgRoleMember.Str() {
		return true
	}
	// Step 2: dynamic permission
	if l.dynamic != nil {
		if _, has := l.dynamic[resource]; has {
			return true
		}
		if _, has := l.dynamic["*"]; has {
			return true
		}
	}
	return false
}

func (l legacyRole) Allows(resource, action string) bool {
	// Step 1: Owner always bypasses and has full access
	if l.name == string(models.OrgRoleOwner) {
		return true
	}
	// Step 2: Merged dynamic DB permission
	if l.dynamic.HasAction(resource, action) {
		return true
	}
	// Step 3: Check custom static roles configured on plugin
	if p, ok := l.static(); ok {
		return p.HasAction(resource, action)
	}
	// Step 4: Built-in static roles
	if l.name == string(models.OrgRoleAdmin) {
		if resource == "organization" && (action == "delete" || action == "update-role") {
			return false
		}
		return true
	}
	if l.name == models.OrgRoleMember.Str() {
		return action == "read" || action == "list" || action == "get"
	}
	return false
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
