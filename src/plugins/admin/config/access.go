package config

import (
	"sort"
	"strings"

	"github.com/better-go-auth/goauth/src/providers/access"
)

// DefaultStatements mirrors better-auth's admin `defaultStatements` (plugins/admin/access/statement.ts).
var DefaultStatements = access.Statements{
	"user": {
		"create", "list", "set-role", "ban", "impersonate", "impersonate-admins",
		"delete", "set-password", "set-email", "get", "update",
	},
	"session": {"list", "revoke", "delete"},
}

// DefaultAC mirrors better-auth's admin `defaultAc`.
var DefaultAC = access.NewAccessControl(DefaultStatements)

// AdminAC mirrors better-auth's `adminAc`: every admin statement except user:impersonate-admins.
var AdminAC = DefaultAC.NewRole(access.Statements{
	"user": {
		"create", "list", "set-role", "ban", "impersonate",
		"delete", "set-password", "set-email", "get", "update",
	},
	"session": {"list", "revoke", "delete"},
})

// UserAC mirrors better-auth's `userAc`: no admin permissions.
var UserAC = DefaultAC.NewRole(access.Statements{"user": {}, "session": {}})

// DefaultRoles returns better-auth's admin `defaultRoles` ({admin, user}).
func DefaultRoles() access.Roles {
	return access.Roles{"admin": AdminAC, "user": UserAC}
}

// Permission requests checked by each admin route (better-auth plugins/admin/routes.ts).
var (
	PermUserCreate      = access.Req(map[string][]string{"user": {"create"}})
	PermUserList        = access.Req(map[string][]string{"user": {"list"}})
	PermUserSetRole     = access.Req(map[string][]string{"user": {"set-role"}})
	PermUserBan         = access.Req(map[string][]string{"user": {"ban"}})
	PermUserImpersonate = access.Req(map[string][]string{"user": {"impersonate"}})
	// PermUserImpersonateAdmins is additionally required to impersonate a user holding an admin role.
	PermUserImpersonateAdmins = access.Req(map[string][]string{"user": {"impersonate-admins"}})
	PermUserDelete            = access.Req(map[string][]string{"user": {"delete"}})
	PermUserSetPassword       = access.Req(map[string][]string{"user": {"set-password"}})
	PermUserSetEmail          = access.Req(map[string][]string{"user": {"set-email"}})
	PermUserGet               = access.Req(map[string][]string{"user": {"get"}})
	PermUserUpdate            = access.Req(map[string][]string{"user": {"update"}})
	PermSessionList           = access.Req(map[string][]string{"session": {"list"}})
	PermSessionRevoke         = access.Req(map[string][]string{"session": {"revoke"}})
)

// CustomRoles reports whether the user configured their own roles (WithRoles/WithAccessControl).
// Without them better-auth's default {admin, user} roles are used (see EffectiveRoles).
func (c AdminConfig) CustomRoles() bool {
	return c.Roles != nil
}

// EffectiveRoles returns the role map used for permission checks.
//   - Custom Roles configured: exactly those roles (better-auth `options.roles`).
//   - Otherwise: better-auth's default {admin, user} roles.
//   - With GoAuth.AdminRolesFullAccess, every AdminRoles entry that is not one of the defaults is
//     mapped to the default admin role (goauth's historical behaviour).
func (c AdminConfig) EffectiveRoles() access.Roles {
	if c.CustomRoles() {
		return c.Roles
	}
	roles := DefaultRoles()
	if !c.GoAuth.AdminRolesFullAccess {
		return roles
	}
	for _, r := range c.AdminRoles {
		if _, ok := roles[r.S()]; !ok && r.S() != "" {
			roles[r.S()] = AdminAC
		}
	}
	return roles
}

// effectiveRole applies better-auth's `role || defaultRole || "user"` fallback.
func (c AdminConfig) effectiveRole(role string) string {
	if role != "" {
		return role
	}
	if c.DefaultRole != "" {
		return c.DefaultRole.S()
	}
	return "user"
}

// IsAdminUserID reports whether userID is listed in AdminUserIDs.
func (c AdminConfig) IsAdminUserID(userID string) bool {
	if userID == "" {
		return false
	}
	for _, id := range c.AdminUserIDs {
		if id == userID {
			return true
		}
	}
	return false
}

// HasPermission mirrors better-auth's admin hasPermission(): AdminUserIDs always pass, otherwise
// any of the user's comma-separated roles must authorize the request.
func (c AdminConfig) HasPermission(userID, role string, request access.Request) bool {
	// Step 1: users listed in adminUserIds bypass role checks
	if c.IsAdminUserID(userID) {
		return true
	}
	// Step 2: no permission requested is never authorized
	if len(request) == 0 {
		return false
	}
	// Step 3: authorize each role (comma separated) against the effective role map
	return access.HasPermission(c.EffectiveRoles(), c.effectiveRole(role), request)
}

// IsAdminTarget reports whether a user counts as an admin for impersonation purposes
// (better-auth: any of their roles is in adminRoles, or their id is in adminUserIds).
func (c AdminConfig) IsAdminTarget(userID, role string) bool {
	if c.IsAdminUserID(userID) {
		return true
	}
	adminRoles := c.AdminRoles
	if len(adminRoles) == 0 {
		adminRoles = DefaultAdminConfig().AdminRoles
	}
	for _, r := range access.SplitRoles(c.effectiveRole(role)) {
		for _, a := range adminRoles {
			if strings.TrimSpace(a.S()) == r {
				return true
			}
		}
	}
	return false
}

// RolesGranting returns the role names (from EffectiveRoles) that authorize request; used to
// pre-filter routes with the role-list middleware. Sorted for determinism.
func (c AdminConfig) RolesGranting(request access.Request) []string {
	roles := c.EffectiveRoles()
	out := make([]string, 0, len(roles))
	for name, r := range roles {
		if r.Authorize(request).Success {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
