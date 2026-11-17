package dtos

import "github.com/better-go-auth/goauth/src/plugins/org/models"

// ─── better-auth access-control DTOs ─────────────────────────────────────────

// HasPermissionInput matches better-auth POST /organization/has-permission.
// `permission` is the deprecated alias of `permissions`.
type HasPermissionInput struct {
	OrganizationID string              `json:"organizationId,omitempty"`
	Permission     map[string][]string `json:"permission,omitempty"`
	Permissions    map[string][]string `json:"permissions,omitempty"`
}

// HasPermissionResponse matches better-auth's `{ error: null, success }`.
type HasPermissionResponse struct {
	Error   *string `json:"error"`
	Success bool    `json:"success"`
}

// CreateRoleInput matches better-auth POST /organization/create-role (plus goauth's optional ops).
type CreateRoleInput struct {
	OrganizationID   string              `json:"organizationId,omitempty"`
	Role             string              `json:"role" minLength:"1"`
	Permission       map[string][]string `json:"permission"`
	AdditionalFields map[string]any      `json:"additionalFields,omitempty"`
	Ops              models.Operations   `json:"ops,omitempty" doc:"goauth extension: operation IDs granted to the role"`
}

// CreateRoleResponse matches better-auth's `{ success, roleData, statements }`.
type CreateRoleResponse struct {
	Success    bool                `json:"success"`
	RoleData   *OrgRoleResponse    `json:"roleData"`
	Statements map[string][]string `json:"statements"`
}

// DeleteRoleInput matches better-auth POST /organization/delete-role (roleName or roleId).
type DeleteRoleInput struct {
	OrganizationID string `json:"organizationId,omitempty"`
	RoleName       string `json:"roleName,omitempty"`
	RoleID         string `json:"roleId,omitempty"`
}

// SuccessResponse is better-auth's `{ success: true }`.
type SuccessResponse struct {
	Success bool `json:"success"`
}

// UpdateRoleData matches better-auth's update-role `data` object.
type UpdateRoleData struct {
	Permission map[string][]string `json:"permission,omitempty"`
	RoleName   string              `json:"roleName,omitempty"`
	Ops        models.Operations   `json:"ops,omitempty" doc:"goauth extension: operation IDs granted to the role"`
}

// UpdateRoleInput matches better-auth POST /organization/update-role.
type UpdateRoleInput struct {
	OrganizationID string         `json:"organizationId,omitempty"`
	RoleName       string         `json:"roleName,omitempty"`
	RoleID         string         `json:"roleId,omitempty"`
	Data           UpdateRoleData `json:"data"`
}

// UpdateRoleResponse matches better-auth's `{ success, roleData }`.
type UpdateRoleResponse struct {
	Success  bool             `json:"success"`
	RoleData *OrgRoleResponse `json:"roleData"`
}
