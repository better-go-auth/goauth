package humaadmin

import (
	"net/http"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/enums"
	"github.com/better-go-auth/goauth/src/common/consts"
	"github.com/danielgtaylor/huma/v2"
)

const (
	// User Management
	AdminListUsers       = consts.OperationId("Ad-1-ListUsers")
	AdminCreateUser      = consts.OperationId("Ad-2-CreateUser")
	AdminSetUserRole     = consts.OperationId("Ad-3-SetUserRole")
	AdminSetUserPassword = consts.OperationId("Ad-4-SetUserPassword")
	AdminRemoveUser      = consts.OperationId("Ad-5-RemoveUser")

	// Moderation & Bans
	AdminBanUser   = consts.OperationId("Ad-6-BanUser")
	AdminUnbanUser = consts.OperationId("Ad-7-UnbanUser")

	// Impersonation
	AdminImpersonateUser   = consts.OperationId("Ad-8-ImpersonateUser")
	AdminStopImpersonating = consts.OperationId("Ad-9-StopImpersonating")

	// Session Control
	AdminListUserSessions   = consts.OperationId("Ad-10-ListUserSessions")
	AdminRevokeUserSession  = consts.OperationId("Ad-11-RevokeUserSession")
	AdminRevokeUserSessions = consts.OperationId("Ad-12-RevokeUserSessions")
)

var defaultAdminRoles = []string{enums.Admin.S(), "admin"}

var AdminPermissionsMap = map[consts.OperationId]models.OperationAccessDto{
	AdminListUsers:          {AllowedRoles: defaultAdminRoles, Description: "List Users (Admin)"},
	AdminCreateUser:         {AllowedRoles: defaultAdminRoles, Description: "Create User (Admin)"},
	AdminSetUserRole:        {AllowedRoles: defaultAdminRoles, Description: "Set User Role (Admin)"},
	AdminSetUserPassword:    {AllowedRoles: defaultAdminRoles, Description: "Set User Password (Admin)"},
	AdminRemoveUser:         {AllowedRoles: defaultAdminRoles, Description: "Remove User (Admin)"},
	AdminBanUser:            {AllowedRoles: defaultAdminRoles, Description: "Ban User (Admin)"},
	AdminUnbanUser:          {AllowedRoles: defaultAdminRoles, Description: "Unban User (Admin)"},
	AdminImpersonateUser:    {AllowedRoles: defaultAdminRoles, Description: "Impersonate User (Admin)"},
	AdminStopImpersonating:  {AllowedRoles: defaultAdminRoles, Description: "Stop Impersonating (Admin)"},
	AdminListUserSessions:   {AllowedRoles: defaultAdminRoles, Description: "List User Sessions (Admin)"},
	AdminRevokeUserSession:  {AllowedRoles: defaultAdminRoles, Description: "Revoke User Session (Admin)"},
	AdminRevokeUserSessions: {AllowedRoles: defaultAdminRoles, Description: "Revoke All User Sessions (Admin)"},
}

// SetupAdminRoutes mounts all Better Auth Admin plugin endpoints onto a Huma API instance.
func SetupAdminRoutes(api huma.API, h *AdminHandler) {
	basePath := h.Cfg.BasePath
	if basePath == "" {
		basePath = "/api/auth"
	}
	basePath = basePath + "/admin"

	// 1. User Management
	huma.Register(api, huma.Operation{
		OperationID: AdminListUsers.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/list-users",
		Summary:     "List Users (Admin)",
		Description: "Search, filter, and paginate users with sorting and advanced field operators.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.Authorize(AdminListUsers, AdminPermissionsMap[AdminListUsers].AllowedRoles)},
	}, h.ListUsers)

	huma.Register(api, huma.Operation{
		OperationID: AdminCreateUser.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/create-user",
		Summary:     "Create User (Admin)",
		Description: "Directly creates a new user with a specified role and password.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.Authorize(AdminCreateUser, AdminPermissionsMap[AdminCreateUser].AllowedRoles)},
	}, h.CreateUser)

	huma.Register(api, huma.Operation{
		OperationID: AdminSetUserRole.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/set-user-role",
		Summary:     "Set User Role (Admin)",
		Description: "Updates the role of a user.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.Authorize(AdminSetUserRole, AdminPermissionsMap[AdminSetUserRole].AllowedRoles)},
	}, h.SetUserRole)

	huma.Register(api, huma.Operation{
		OperationID: AdminSetUserPassword.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/set-user-password",
		Summary:     "Set User Password (Admin)",
		Description: "Overrides a user's password directly.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.Authorize(AdminSetUserPassword, AdminPermissionsMap[AdminSetUserPassword].AllowedRoles)},
	}, h.SetUserPassword)

	huma.Register(api, huma.Operation{
		OperationID: AdminRemoveUser.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/remove-user",
		Summary:     "Remove User (Admin)",
		Description: "Permanently deletes a user and all their sessions and accounts.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.Authorize(AdminRemoveUser, AdminPermissionsMap[AdminRemoveUser].AllowedRoles)},
	}, h.RemoveUser)

	// 2. Moderation & Bans
	huma.Register(api, huma.Operation{
		OperationID: AdminBanUser.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/ban-user",
		Summary:     "Ban User (Admin)",
		Description: "Bans a user and immediately revokes all their active sessions.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.Authorize(AdminBanUser, AdminPermissionsMap[AdminBanUser].AllowedRoles)},
	}, h.BanUser)

	huma.Register(api, huma.Operation{
		OperationID: AdminUnbanUser.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/unban-user",
		Summary:     "Unban User (Admin)",
		Description: "Removes a ban from a user.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.Authorize(AdminUnbanUser, AdminPermissionsMap[AdminUnbanUser].AllowedRoles)},
	}, h.UnbanUser)

	// 3. Impersonation
	huma.Register(api, huma.Operation{
		OperationID: AdminImpersonateUser.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/impersonate-user",
		Summary:     "Impersonate User (Admin)",
		Description: "Creates an authenticated session acting as the target user with impersonatedBy recorded.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.Authorize(AdminImpersonateUser, AdminPermissionsMap[AdminImpersonateUser].AllowedRoles)},
	}, h.ImpersonateUser)

	huma.Register(api, huma.Operation{
		OperationID: AdminStopImpersonating.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/stop-impersonating",
		Summary:     "Stop Impersonating (Admin)",
		Description: "Terminates the active impersonation session and clears session cookies.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.Authorize(AdminStopImpersonating, AdminPermissionsMap[AdminStopImpersonating].AllowedRoles)},
	}, h.StopImpersonating)

	// 4. Session Control
	huma.Register(api, huma.Operation{
		OperationID: AdminListUserSessions.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/list-user-sessions",
		Summary:     "List User Sessions (Admin)",
		Description: "Lists all active sessions for a given user.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.Authorize(AdminListUserSessions, AdminPermissionsMap[AdminListUserSessions].AllowedRoles)},
	}, h.ListUserSessions)

	huma.Register(api, huma.Operation{
		OperationID: AdminRevokeUserSession.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/revoke-user-session",
		Summary:     "Revoke User Session (Admin)",
		Description: "Terminates a specific session for a user by token or ID.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.Authorize(AdminRevokeUserSession, AdminPermissionsMap[AdminRevokeUserSession].AllowedRoles)},
	}, h.RevokeUserSession)

	huma.Register(api, huma.Operation{
		OperationID: AdminRevokeUserSessions.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/revoke-user-sessions",
		Summary:     "Revoke All User Sessions (Admin)",
		Description: "Terminates all active sessions for a target user.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.Authorize(AdminRevokeUserSessions, AdminPermissionsMap[AdminRevokeUserSessions].AllowedRoles)},
	}, h.RevokeUserSessions)
}
