package dtos

import (
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/models/enums"
)

// ─── User Management DTOs ───────────────────────────────────────────────────

// AdminListUsersInput specifies query parameters and filters for listing users.
type AdminListUsersInput struct {
	Limit          *int    `json:"limit,omitempty" doc:"Max number of records to return"`
	Offset         *int    `json:"offset,omitempty" doc:"Number of records to skip"`
	SearchValue    *string `json:"searchValue,omitempty" doc:"Search query string"`
	SearchField    *string `json:"searchField,omitempty" doc:"Field to search against (name, email, etc.)"`
	SortBy         *string `json:"sortBy,omitempty" doc:"Field to sort results by"`
	SortDirection  *string `json:"sortDirection,omitempty" doc:"Sort direction: asc or desc"`
	FilterField    *string `json:"filterField,omitempty" doc:"Field to filter on (e.g. role, banned, email)"`
	FilterOperator *string `json:"filterOperator,omitempty" doc:"Operator: eq, ne, lt, lte, gt, gte, contains, starts_with, ends_with"`
	FilterValue    *string `json:"filterValue,omitempty" doc:"Value for the filter operator"`
}

// AdminListUsersResponse matches the output format of POST /api/auth/admin/list-users.
type AdminListUsersResponse struct {
	Users []dtos.UserResponse `json:"users"`
	Total int64               `json:"total"`
}

// AdminCreateUserInput represents the request payload for POST /api/auth/admin/create-user.
type AdminCreateUserInput struct {
	Email    string                 `json:"email" required:"true" doc:"User email address"`
	Password string                 `json:"password" required:"true" doc:"User initial password"`
	Name     string                 `json:"name" required:"true" doc:"User display name"`
	Role     enums.Role                `json:"role,omitempty" doc:"Role to assign (e.g. user, admin)"`
	Data     map[string]interface{} `json:"data,omitempty" doc:"Additional custom user metadata"`
}

// AdminUserWrapperResponse matches endpoints that return { "user": User }.
type AdminUserWrapperResponse struct {
	User *dtos.UserResponse `json:"user"`
}

// AdminSetUserRoleInput represents the payload for POST /api/auth/admin/set-user-role.
type AdminSetUserRoleInput struct {
	UserID string     `json:"userId" required:"true" doc:"ID of the user"`
	Role   enums.Role `json:"role" required:"true" doc:"New role to assign"`
}

// AdminSetRoleInput is an alias matching better-auth's POST /admin/set-role body.
type AdminSetRoleInput = AdminSetUserRoleInput

// AdminSetUserRoleResponse is the response for POST /api/auth/admin/set-user-role.
type AdminSetUserRoleResponse struct {
	User   *dtos.UserResponse `json:"user,omitempty"`
	Status bool               `json:"status,omitempty"`
}

// AdminSetUserPasswordInput represents the payload for POST /api/auth/admin/set-user-password.
type AdminSetUserPasswordInput struct {
	UserID      string `json:"userId" required:"true" doc:"ID of the target user"`
	NewPassword string `json:"newPassword" required:"true" doc:"New password to set"`
}

// AdminRemoveUserInput represents the payload for POST /api/auth/admin/remove-user.
type AdminRemoveUserInput struct {
	UserID string `json:"userId" required:"true" doc:"ID of the user to remove"`
}

// ─── Moderation / Ban DTOs ───────────────────────────────────────────────────

// AdminBanUserInput represents the payload for POST /api/auth/admin/ban-user.
type AdminBanUserInput struct {
	UserID       string  `json:"userId" required:"true" doc:"ID of the user to ban"`
	BanReason    *string `json:"banReason,omitempty" doc:"Reason for the ban"`
	BanExpiresIn *int64  `json:"banExpiresIn,omitempty" doc:"Duration in seconds before ban expires (nil = permanent)"`
}

// AdminBanUserResponse is the response for POST /api/auth/admin/ban-user.
type AdminBanUserResponse struct {
	User   *dtos.UserResponse `json:"user,omitempty"`
	Status bool               `json:"status,omitempty"`
}

// AdminUnbanUserInput represents the payload for POST /api/auth/admin/unban-user.
type AdminUnbanUserInput struct {
	UserID string `json:"userId" required:"true" doc:"ID of the user to unban"`
}

// AdminUnbanUserResponse is the response for POST /api/auth/admin/unban-user.
type AdminUnbanUserResponse struct {
	User   *dtos.UserResponse `json:"user,omitempty"`
	Status bool               `json:"status,omitempty"`
}

// ─── Impersonation DTOs ──────────────────────────────────────────────────────

// AdminImpersonateUserInput represents the payload for POST /api/auth/admin/impersonate-user.
type AdminImpersonateUserInput struct {
	UserID string `json:"userId" required:"true" doc:"ID of the user to impersonate"`
}

// AdminStopImpersonatingInput represents the payload for POST /api/auth/admin/stop-impersonating.
type AdminStopImpersonatingInput struct{}

// ─── Session Control DTOs ────────────────────────────────────────────────────

// AdminListUserSessionsInput represents the payload for POST /api/auth/admin/list-user-sessions.
type AdminListUserSessionsInput struct {
	UserID string `json:"userId" required:"true" doc:"ID of the user whose sessions to list"`
}

// AdminListUserSessionsResponse matches the response of POST /api/auth/admin/list-user-sessions.
type AdminListUserSessionsResponse struct {
	Sessions []dtos.SessionData `json:"sessions"`
}

// AdminRevokeUserSessionInput represents the payload for POST /api/auth/admin/revoke-user-session.
type AdminRevokeUserSessionInput struct {
	SessionToken *string `json:"sessionToken,omitempty" doc:"Token of the session to revoke"`
	ID           *string `json:"id,omitempty" doc:"ID of the session to revoke"`
}

// AdminRevokeUserSessionsInput represents the payload for POST /api/auth/admin/revoke-user-sessions.
type AdminRevokeUserSessionsInput struct {
	UserID string `json:"userId" required:"true" doc:"ID of the user whose sessions to terminate"`
}

// AdminStatusResponse is a generic status response { "status": true }.
type AdminStatusResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message,omitempty"`
}

// AdminListUsersQuery represents query parameters for GET /api/auth/admin/list-users.
type AdminListUsersQuery struct {
	Limit          int    `query:"limit,omitempty" doc:"Max number of records to return"`
	Offset         int    `query:"offset,omitempty" doc:"Number of records to skip"`
	SearchValue    string `query:"searchValue,omitempty" doc:"Search query string"`
	SearchField    string `query:"searchField,omitempty" doc:"Field to search against (name, email, etc.)"`
	SortBy         string `query:"sortBy,omitempty" doc:"Field to sort results by"`
	SortDirection  string `query:"sortDirection,omitempty" doc:"Sort direction: asc or desc"`
	FilterField    string `query:"filterField,omitempty" doc:"Field to filter on (e.g. role, banned, email)"`
	FilterOperator string `query:"filterOperator,omitempty" doc:"Operator: eq, ne, lt, lte, gt, gte, contains, starts_with, ends_with"`
	FilterValue    string `query:"filterValue,omitempty" doc:"Value for the filter operator"`
}

// AdminGetUserInput represents input for GET/POST /api/auth/admin/get-user.
type AdminGetUserInput struct {
	ID     string `query:"id" json:"id,omitempty" doc:"ID of the user"`
	UserID string `query:"userId" json:"userId,omitempty" doc:"Alias for user ID"`
}

// AdminUpdateUserInput represents payload for POST /api/auth/admin/update-user.
type AdminUpdateUserInput struct {
	UserID string                 `json:"userId" required:"true" doc:"ID of the user to update"`
	Data   map[string]interface{} `json:"data" required:"true" doc:"Fields to update"`
}

// AdminHasPermissionInput represents payload for POST /api/auth/admin/has-permission.
type AdminHasPermissionInput struct {
	UserID      string              `json:"userId,omitempty" doc:"The user id to check"`
	Role        string              `json:"role,omitempty" doc:"The role to check"`
	Permission  map[string][]string `json:"permission,omitempty" doc:"Permission to check"`
	Permissions map[string][]string `json:"permissions,omitempty" doc:"Permissions to check"`
}

// AdminHasPermissionResponse represents the response of POST /api/auth/admin/has-permission.
type AdminHasPermissionResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

