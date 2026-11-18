package config

import (
	"time"

	"github.com/better-go-auth/goauth/src/models/enums"
	"github.com/better-go-auth/goauth/src/providers/access"
)

// AdminConfig holds optional configuration for the Admin plugin.
type AdminConfig struct {
	// AdminRoles mirrors better-auth's `adminRoles`: the roles that count as admins (e.g. for the
	// impersonation guard). Permissions on /admin/* come from Roles / the default {admin, user} roles,
	// like better-auth; GoAuth.AdminRolesFullAccess restores goauth's old "every AdminRoles entry can use
	// every /admin/* route" mapping. Default: ["admin"]
	AdminRoles []enums.Role

	// DefaultRole is the fallback role assigned to newly created users if unspecified.
	// Default: "user"
	DefaultRole enums.Role

	// ImpersonationSessionExpiresIn controls the duration of an impersonation session.
	// Default: same as AuthConfig.Session.ExpiresIn (or 7 days)
	ImpersonationSessionExpiresIn time.Duration

	// AccessControl mirrors better-auth's admin `ac` option: the statements (resources/actions)
	// custom roles are built from. Default: DefaultAC (user/session statements).
	AccessControl *access.AccessControl

	// Roles mirrors better-auth's admin `roles` option. nil means better-auth's default
	// {admin, user} roles (see EffectiveRoles). When set, only these roles are used.
	Roles access.Roles

	// AdminUserIDs mirrors better-auth's `adminUserIds`: these users pass every admin permission
	// check regardless of their role.
	AdminUserIDs []string

	// AllowImpersonatingAdmins mirrors better-auth's `allowImpersonatingAdmins`. When false
	// (default), impersonating a user holding an admin role (or listed in AdminUserIDs) requires
	// the user:impersonate-admins permission.
	AllowImpersonatingAdmins bool

	// GoAuth holds admin options better-auth doesn't have.
	GoAuth AdminGoAuth
}

// AdminGoAuth holds admin options better-auth doesn't have.
type AdminGoAuth struct {
	// AdminRolesFullAccess maps every AdminRoles entry that is not a configured role to better-auth's
	// default admin role, so it can use every /admin/* route (goauth's behaviour before better-auth access
	// control). Ignored when Roles is set. Default false: like better-auth, a role without statements in
	// the role map has no admin permissions.
	AdminRolesFullAccess bool
}

// DefaultAdminConfig returns the default configuration for the admin plugin.
func DefaultAdminConfig() AdminConfig {
	return AdminConfig{
		AdminRoles:                    []enums.Role{enums.Admin},
		DefaultRole:                   enums.User,
		ImpersonationSessionExpiresIn: 7 * 24 * time.Hour,
	}
}
