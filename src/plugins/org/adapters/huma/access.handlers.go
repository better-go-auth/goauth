package humaorg

import (
	"context"
	"net/http"

	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/models/dtos"
	orgdtos "github.com/better-go-auth/goauth/src/plugins/org/dtos"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
	orgerrors "github.com/better-go-auth/goauth/src/plugins/org/org-errors"
	orgsvc "github.com/better-go-auth/goauth/src/plugins/org/services"
	"github.com/better-go-auth/goauth/src/providers/access"
	"github.com/danielgtaylor/huma/v2"
)

// ─── Inputs / Outputs ─────────────────────────────────────────────────────────

type (
	HasPermissionInput = humatypes.HumaReqBody[orgdtos.HasPermissionInput]
	CreateRoleInput    = humatypes.HumaReqBody[orgdtos.CreateRoleInput]
	DeleteRoleInput    = humatypes.HumaReqBody[orgdtos.DeleteRoleInput]
	UpdateRoleInput    = humatypes.HumaReqBody[orgdtos.UpdateRoleInput]
)

// ListRolesInput is the query of GET /organization/list-roles.
type ListRolesInput struct {
	humatypes.AuthHeaders
	OrganizationID string `query:"organizationId,omitempty" doc:"Organization ID (defaults to the active organization)"`
}

// GetRoleInput is the query of GET /organization/get-role.
type GetRoleInput struct {
	humatypes.AuthHeaders
	OrganizationID string `query:"organizationId,omitempty" doc:"Organization ID (defaults to the active organization)"`
	RoleName       string `query:"roleName,omitempty" doc:"Role name"`
	RoleID         string `query:"roleId,omitempty" doc:"Role id"`
}

// setupAccessControlRoutes registers /organization/has-permission and, when dynamic access control
// is enabled (like better-auth), the role CRUD endpoints.
func setupAccessControlRoutes(api huma.API, h *OrgHandler, path string) {
	tags := []string{"Org-AccessControl"}
	huma.Register(api, huma.Operation{
		OperationID: OrHasPermission.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/has-permission",
		Summary:     "Check Organization Permission",
		Description: "Checks whether the caller's member role in the organization grants the permissions.",
		Tags:        tags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
		Metadata:    rawBodyMeta(),
	}, h.HasPermission)

	if !h.Org.DynamicAccessControlEnabled() {
		return
	}
	huma.Register(api, huma.Operation{
		OperationID: OrCreateRole.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/create-role",
		Summary:     "Create Organization Role",
		Description: "Creates a dynamic role (requires ac:create and every granted permission).",
		Tags:        tags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
		Metadata:    rawBodyMeta(),
	}, h.CreateRole)
	huma.Register(api, huma.Operation{
		OperationID: OrDeleteRole.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/delete-role",
		Summary:     "Delete Organization Role",
		Description: "Deletes a dynamic role by roleName or roleId (requires ac:delete).",
		Tags:        tags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
		Metadata:    rawBodyMeta(),
	}, h.DeleteRole)
	huma.Register(api, huma.Operation{
		OperationID: OrListRoles.Str(),
		Method:      http.MethodGet,
		Path:        path + "/organization/list-roles",
		Summary:     "List Organization Roles",
		Description: "Lists the organization's dynamic roles (requires ac:read).",
		Tags:        tags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
		Metadata:    rawBodyMeta(),
	}, h.ListRoles)
	huma.Register(api, huma.Operation{
		OperationID: OrGetRole.Str(),
		Method:      http.MethodGet,
		Path:        path + "/organization/get-role",
		Summary:     "Get Organization Role",
		Description: "Reads a dynamic role by roleName or roleId (requires ac:read).",
		Tags:        tags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
		Metadata:    rawBodyMeta(),
	}, h.GetRole)
	huma.Register(api, huma.Operation{
		OperationID: OrUpdateRole.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/update-role",
		Summary:     "Update Organization Role",
		Description: "Updates a dynamic role's permission and/or name (requires ac:update and every granted permission).",
		Tags:        tags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
		Metadata:    rawBodyMeta(),
	}, h.UpdateRole)
}

// resolveOrgID returns orgID, or the session's active organization, or missing.
func resolveOrgID(session *dtos.SessionWithUser, orgID string, missing error) (string, error) {
	if orgID != "" {
		return orgID, nil
	}
	if session.Session.ActiveOrganizationID != nil && *session.Session.ActiveOrganizationID != "" {
		return *session.Session.ActiveOrganizationID, nil
	}
	return "", missing
}

// HasPermission handles POST /organization/has-permission (better-auth createHasPermission).
func (h *OrgHandler) HasPermission(ctx context.Context, input *HasPermissionInput) (*humatypes.HumaRes[orgdtos.HasPermissionResponse], error) {
	// Step 1: authenticate and resolve the organization
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	orgID, err := resolveOrgID(session, input.Body.OrganizationID, orgerrors.ErrNoActiveOrganization)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	// Step 2: the caller must be a member
	member, err := h.Org.GetMember(ctx, orgID, session.User.ID)
	if err != nil || member == nil {
		return nil, humatypes.RespondErr(orgerrors.ErrUserNotMemberOfOrganization)
	}
	// Step 3: evaluate (`permission` is the deprecated alias)
	perms := input.Body.Permissions
	if len(perms) == 0 {
		perms = input.Body.Permission
	}
	ok, err := h.Org.HasPermissions(ctx, orgID, string(member.Role), access.Req(perms))
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeResPtr(&orgdtos.HasPermissionResponse{Success: ok}, http.StatusOK), nil
}

// CreateRole handles POST /organization/create-role.
func (h *OrgHandler) CreateRole(ctx context.Context, input *CreateRoleInput) (*humatypes.HumaRes[orgdtos.CreateRoleResponse], error) {
	// Step 1: authenticate and resolve the organization
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	orgID, err := resolveOrgID(session, input.Body.OrganizationID, orgerrors.ErrMustBeInOrgToCreateRole)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	// Step 2: create (the service applies every better-auth check)
	perm := models.Permission(input.Body.Permission)
	if perm == nil {
		perm = models.Permission{}
	}
	role, err := h.Org.CreateRoleWithOps(ctx, orgID, input.Body.Role, perm, input.Body.Ops, session.User.ID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeResPtr(&orgdtos.CreateRoleResponse{
		Success:    true,
		RoleData:   orgdtos.OrgRoleToResponse(role),
		Statements: role.Permission,
	}, http.StatusOK), nil
}

// DeleteRole handles POST /organization/delete-role.
func (h *OrgHandler) DeleteRole(ctx context.Context, input *DeleteRoleInput) (*humatypes.HumaRes[orgdtos.SuccessResponse], error) {
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	orgID, err := resolveOrgID(session, input.Body.OrganizationID, orgerrors.ErrNoActiveOrganization)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	if err := h.Org.DeleteRoleBy(ctx, orgID, input.Body.RoleName, input.Body.RoleID, session.User.ID); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeResPtr(&orgdtos.SuccessResponse{Success: true}, http.StatusOK), nil
}

// ListRoles handles GET /organization/list-roles.
func (h *OrgHandler) ListRoles(ctx context.Context, input *ListRolesInput) (*humatypes.HumaRes[[]orgdtos.OrgRoleResponse], error) {
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	orgID, err := resolveOrgID(session, input.OrganizationID, orgerrors.ErrNoActiveOrganization)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	roles, err := h.Org.ListRoles(ctx, orgID, session.User.ID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	out := make([]orgdtos.OrgRoleResponse, 0, len(roles))
	for i := range roles {
		out = append(out, *orgdtos.OrgRoleToResponse(&roles[i]))
	}
	return humatypes.MakeResPtr(&out, http.StatusOK), nil
}

// GetRole handles GET /organization/get-role.
func (h *OrgHandler) GetRole(ctx context.Context, input *GetRoleInput) (*humatypes.HumaRes[orgdtos.OrgRoleResponse], error) {
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	orgID, err := resolveOrgID(session, input.OrganizationID, orgerrors.ErrNoActiveOrganization)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	role, err := h.Org.GetRoleBy(ctx, orgID, input.RoleName, input.RoleID, session.User.ID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeResPtr(orgdtos.OrgRoleToResponse(role), http.StatusOK), nil
}

// UpdateRole handles POST /organization/update-role.
func (h *OrgHandler) UpdateRole(ctx context.Context, input *UpdateRoleInput) (*humatypes.HumaRes[orgdtos.UpdateRoleResponse], error) {
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	orgID, err := resolveOrgID(session, input.Body.OrganizationID, orgerrors.ErrNoActiveOrganization)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	data := orgsvc.UpdateRoleData{RoleName: input.Body.Data.RoleName, Ops: input.Body.Data.Ops}
	if input.Body.Data.Permission != nil {
		data.Permission = models.Permission(input.Body.Data.Permission)
	}
	role, err := h.Org.UpdateRoleBy(ctx, orgID, input.Body.RoleName, input.Body.RoleID, data, session.User.ID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeResPtr(&orgdtos.UpdateRoleResponse{Success: true, RoleData: orgdtos.OrgRoleToResponse(role)}, http.StatusOK), nil
}
