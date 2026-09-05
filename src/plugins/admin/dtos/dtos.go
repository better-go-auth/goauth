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
