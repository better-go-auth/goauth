package humaadmin

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// SetupAdminRoutes mounts all Better Auth Admin plugin endpoints onto a Huma API instance.
func SetupAdminRoutes(api huma.API, h *AdminHandler) {
	basePath := h.Cfg.BasePath
	if basePath == "" {
		basePath = "/api/auth"
	}
	basePath = basePath + "/admin"

	// 1. User Management
	huma.Register(api, huma.Operation{
		OperationID: "AUTH_Admin_ListUsers",
		Method:      http.MethodPost,
		Path:        basePath + "/list-users",
		Summary:     "List Users (Admin)",
		Description: "Search, filter, and paginate users with sorting and advanced field operators.",
		Tags:        []string{"Admin"},
	}, h.ListUsers)

	huma.Register(api, huma.Operation{
		OperationID: "AUTH_Admin_CreateUser",
		Method:      http.MethodPost,
		Path:        basePath + "/create-user",
		Summary:     "Create User (Admin)",
		Description: "Directly creates a new user with a specified role and password.",
		Tags:        []string{"Admin"},
	}, h.CreateUser)

	huma.Register(api, huma.Operation{
		OperationID: "AUTH_Admin_SetUserRole",
		Method:      http.MethodPost,
		Path:        basePath + "/set-user-role",
		Summary:     "Set User Role (Admin)",
		Description: "Updates the role of a user.",
		Tags:        []string{"Admin"},
	}, h.SetUserRole)

	huma.Register(api, huma.Operation{
		OperationID: "AUTH_Admin_SetUserPassword",
		Method:      http.MethodPost,
		Path:        basePath + "/set-user-password",
		Summary:     "Set User Password (Admin)",
		Description: "Overrides a user's password directly.",
		Tags:        []string{"Admin"},
	}, h.SetUserPassword)

	huma.Register(api, huma.Operation{
		OperationID: "AUTH_Admin_RemoveUser",
		Method:      http.MethodPost,
		Path:        basePath + "/remove-user",
		Summary:     "Remove User (Admin)",
		Description: "Permanently deletes a user and all their sessions and accounts.",
		Tags:        []string{"Admin"},
	}, h.RemoveUser)

	// 2. Moderation & Bans
	huma.Register(api, huma.Operation{
		OperationID: "AUTH_Admin_BanUser",
		Method:      http.MethodPost,
		Path:        basePath + "/ban-user",
		Summary:     "Ban User (Admin)",
		Description: "Bans a user and immediately revokes all their active sessions.",
		Tags:        []string{"Admin"},
	}, h.BanUser)

	huma.Register(api, huma.Operation{
		OperationID: "AUTH_Admin_UnbanUser",
		Method:      http.MethodPost,
		Path:        basePath + "/unban-user",
		Summary:     "Unban User (Admin)",
		Description: "Removes a ban from a user.",
		Tags:        []string{"Admin"},
	}, h.UnbanUser)

	// 3. Impersonation
	huma.Register(api, huma.Operation{
		OperationID: "AUTH_Admin_ImpersonateUser",
		Method:      http.MethodPost,
		Path:        basePath + "/impersonate-user",
		Summary:     "Impersonate User (Admin)",
		Description: "Creates an authenticated session acting as the target user with impersonatedBy recorded.",
		Tags:        []string{"Admin"},
	}, h.ImpersonateUser)

	huma.Register(api, huma.Operation{
		OperationID: "AUTH_Admin_StopImpersonating",
		Method:      http.MethodPost,
		Path:        basePath + "/stop-impersonating",
		Summary:     "Stop Impersonating (Admin)",
		Description: "Terminates the active impersonation session and clears session cookies.",
		Tags:        []string{"Admin"},
	}, h.StopImpersonating)

	// 4. Session Control
	huma.Register(api, huma.Operation{
		OperationID: "AUTH_Admin_ListUserSessions",
		Method:      http.MethodPost,
		Path:        basePath + "/list-user-sessions",
		Summary:     "List User Sessions (Admin)",
		Description: "Lists all active sessions for a given user.",
		Tags:        []string{"Admin"},
	}, h.ListUserSessions)

	huma.Register(api, huma.Operation{
		OperationID: "AUTH_Admin_RevokeUserSession",
		Method:      http.MethodPost,
		Path:        basePath + "/revoke-user-session",
		Summary:     "Revoke User Session (Admin)",
		Description: "Terminates a specific session for a user by token or ID.",
		Tags:        []string{"Admin"},
	}, h.RevokeUserSession)

	huma.Register(api, huma.Operation{
		OperationID: "AUTH_Admin_RevokeUserSessions",
		Method:      http.MethodPost,
		Path:        basePath + "/revoke-user-sessions",
		Summary:     "Revoke All User Sessions (Admin)",
		Description: "Terminates all active sessions for a target user.",
		Tags:        []string{"Admin"},
	}, h.RevokeUserSessions)
}
