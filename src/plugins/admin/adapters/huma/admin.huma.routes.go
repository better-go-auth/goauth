package humaadmin

import (
	"net/http"

	"github.com/better-go-auth/goauth/src/common/consts"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/enums"
	adminconfig "github.com/better-go-auth/goauth/src/plugins/admin/config"
	"github.com/better-go-auth/goauth/src/providers/access"
	"github.com/danielgtaylor/huma/v2"
)

const (
	// User Management
	AdminListUsers       = consts.OperationId("Ad-1-ListUsers")
	AdminListUsersQuery  = consts.OperationId("Ad-1-ListUsersQuery")
	AdminCreateUser      = consts.OperationId("Ad-2-CreateUser")
	AdminSetUserRole     = consts.OperationId("Ad-3-SetUserRole")
	AdminSetRole         = consts.OperationId("Ad-3-SetRole")
	AdminSetUserPassword = consts.OperationId("Ad-4-SetUserPassword")
	AdminRemoveUser      = consts.OperationId("Ad-5-RemoveUser")
	AdminGetUser         = consts.OperationId("Ad-13-GetUser")
	AdminUpdateUser      = consts.OperationId("Ad-14-UpdateUser")
	AdminHasPermission   = consts.OperationId("Ad-15-HasPermission")

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

// defaultAdminRoles lists the roles that pass every admin route with the default configuration
// (better-auth's default admin role). The live list per configuration is AdminHandler.RouteRoles.
var defaultAdminRoles = []string{enums.Admin.S()}

var AdminPermissionsMap = map[consts.OperationId]models.OperationAccessDto{
	AdminListUsers:       {AllowedRoles: defaultAdminRoles, Description: "List Users (Admin)"},
	AdminListUsersQuery:  {AllowedRoles: defaultAdminRoles, Description: "List Users Query (Admin)"},
	AdminCreateUser:      {AllowedRoles: defaultAdminRoles, Description: "Create User (Admin)"},
	AdminSetUserRole:     {AllowedRoles: defaultAdminRoles, Description: "Set User Role (Admin)"},
	AdminSetRole:         {AllowedRoles: defaultAdminRoles, Description: "Set Role (Admin)"},
	AdminSetUserPassword: {AllowedRoles: defaultAdminRoles, Description: "Set User Password (Admin)"},
	AdminRemoveUser:      {AllowedRoles: defaultAdminRoles, Description: "Remove User (Admin)"},
	AdminGetUser:         {AllowedRoles: defaultAdminRoles, Description: "Get User (Admin)"},
	AdminUpdateUser:      {AllowedRoles: defaultAdminRoles, Description: "Update User (Admin)"},
	// any authenticated user may check their own permissions (better-auth /admin/has-permission)
	AdminHasPermission:      {AllowedRoles: []string{}, Description: "Has Permission (Admin)"},
	AdminBanUser:            {AllowedRoles: defaultAdminRoles, Description: "Ban User (Admin)"},
	AdminUnbanUser:          {AllowedRoles: defaultAdminRoles, Description: "Unban User (Admin)"},
	AdminImpersonateUser:    {AllowedRoles: defaultAdminRoles, Description: "Impersonate User (Admin)"},
	AdminStopImpersonating:  {AllowedRoles: defaultAdminRoles, Description: "Stop Impersonating (Admin)"},
	AdminListUserSessions:   {AllowedRoles: defaultAdminRoles, Description: "List User Sessions (Admin)"},
	AdminRevokeUserSession:  {AllowedRoles: defaultAdminRoles, Description: "Revoke User Session (Admin)"},
	AdminRevokeUserSessions: {AllowedRoles: defaultAdminRoles, Description: "Revoke All User Sessions (Admin)"},
}

// RoutePermissions maps each admin operation to the better-auth permission its handler checks
// (plugins/admin/routes.ts). The handler is authoritative (AdminHandler.RequirePermission), so
// denied calls get better-auth's specific error codes (e.g. YOU_ARE_NOT_ALLOWED_TO_LIST_USERS)
// instead of a generic role-list 403. AdminHandler.RouteRoles reports, for the active
// configuration, which roles pass each route; AdminPermissionsMap above lists the defaults.
// An empty request means "any authenticated user" (has-permission).
var RoutePermissions = map[consts.OperationId]access.Request{
	AdminListUsers:          adminconfig.PermUserList,
	AdminListUsersQuery:     adminconfig.PermUserList,
	AdminCreateUser:         adminconfig.PermUserCreate,
	AdminSetUserRole:        adminconfig.PermUserSetRole,
	AdminSetRole:            adminconfig.PermUserSetRole,
	AdminSetUserPassword:    adminconfig.PermUserSetPassword,
	AdminRemoveUser:         adminconfig.PermUserDelete,
	AdminGetUser:            adminconfig.PermUserGet,
	AdminUpdateUser:         adminconfig.PermUserUpdate,
	AdminHasPermission:      {},
	AdminBanUser:            adminconfig.PermUserBan,
	AdminUnbanUser:          adminconfig.PermUserBan,
	AdminImpersonateUser:    adminconfig.PermUserImpersonate,
	AdminListUserSessions:   adminconfig.PermSessionList,
	AdminRevokeUserSession:  adminconfig.PermSessionRevoke,
	AdminRevokeUserSessions: adminconfig.PermSessionRevoke,
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
		OperationID: AdminListUsersQuery.Str(),
		Method:      http.MethodGet,
		Path:        basePath + "/list-users",
		Summary:     "List Users (Admin)",
		Description: "Search, filter, and paginate users with sorting and advanced field operators.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.ListUsersQuery)

	huma.Register(api, huma.Operation{
		OperationID: AdminListUsers.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/list-users",
		Summary:     "List Users (Admin) [Legacy]",
		Description: "Search, filter, and paginate users via POST body.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.ListUsers)

	huma.Register(api, huma.Operation{
		OperationID: AdminCreateUser.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/create-user",
		Summary:     "Create User (Admin)",
		Description: "Directly creates a new user with a specified role and password.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.CreateUser)

	huma.Register(api, huma.Operation{
		OperationID: AdminSetRole.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/set-role",
		Summary:     "Set User Role (Admin)",
		Description: "Updates the role of a user.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.SetUserRole)

	huma.Register(api, huma.Operation{
		OperationID: AdminSetUserRole.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/set-user-role",
		Summary:     "Set User Role (Admin) [Legacy]",
		Description: "Updates the role of a user.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.SetUserRole)

	huma.Register(api, huma.Operation{
		OperationID: AdminGetUser.Str(),
		Method:      http.MethodGet,
		Path:        basePath + "/get-user",
		Summary:     "Get User (Admin)",
		Description: "Retrieves details of an existing user.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.GetUser)

	huma.Register(api, huma.Operation{
		OperationID: AdminUpdateUser.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/update-user",
		Summary:     "Update User (Admin)",
		Description: "Updates fields of an existing user.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.UpdateUser)

	huma.Register(api, huma.Operation{
		OperationID: AdminHasPermission.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/has-permission",
		Summary:     "Check User Permission (Admin)",
		Description: "Checks if a user or role has the specified permissions.",
		Tags:        []string{"Admin"},
		// any authenticated user: the session user's own role is checked (better-auth)
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.HasPermission)

	huma.Register(api, huma.Operation{
		OperationID: AdminSetUserPassword.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/set-user-password",
		Summary:     "Set User Password (Admin)",
		Description: "Overrides a user's password directly.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.SetUserPassword)

	huma.Register(api, huma.Operation{
		OperationID: AdminRemoveUser.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/remove-user",
		Summary:     "Remove User (Admin)",
		Description: "Permanently deletes a user and all their sessions and accounts.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.RemoveUser)

	// 2. Moderation & Bans
	huma.Register(api, huma.Operation{
		OperationID: AdminBanUser.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/ban-user",
		Summary:     "Ban User (Admin)",
		Description: "Bans a user and immediately revokes all their active sessions.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.BanUser)

	huma.Register(api, huma.Operation{
		OperationID: AdminUnbanUser.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/unban-user",
		Summary:     "Unban User (Admin)",
		Description: "Removes a ban from a user.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.UnbanUser)

	// 3. Impersonation
	huma.Register(api, huma.Operation{
		OperationID: AdminImpersonateUser.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/impersonate-user",
		Summary:     "Impersonate User (Admin)",
		Description: "Creates an authenticated session acting as the target user with impersonatedBy recorded.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.ImpersonateUser)

	huma.Register(api, huma.Operation{
		OperationID: AdminStopImpersonating.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/stop-impersonating",
		Summary:     "Stop Impersonating (Admin)",
		Description: "Terminates the active impersonation session and clears session cookies.",
		Tags:        []string{"Admin"},
		// the caller holds the impersonated user's token, so no admin role check; the service verifies impersonatedBy
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.StopImpersonating)

	// 4. Session Control
	huma.Register(api, huma.Operation{
		OperationID: AdminListUserSessions.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/list-user-sessions",
		Summary:     "List User Sessions (Admin)",
		Description: "Lists all active sessions for a given user.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.ListUserSessions)

	huma.Register(api, huma.Operation{
		OperationID: AdminRevokeUserSession.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/revoke-user-session",
		Summary:     "Revoke User Session (Admin)",
		Description: "Terminates a specific session for a user by token or ID.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.RevokeUserSession)

	huma.Register(api, huma.Operation{
		OperationID: AdminRevokeUserSessions.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/revoke-user-sessions",
		Summary:     "Revoke All User Sessions (Admin)",
		Description: "Terminates all active sessions for a target user.",
		Tags:        []string{"Admin"},
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.RevokeUserSessions)
}
