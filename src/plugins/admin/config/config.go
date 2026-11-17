package config

import (
	"time"

	"github.com/better-go-auth/goauth/src/models/enums"
	"github.com/better-go-auth/goauth/src/providers/access"
)

// AdminConfig holds optional configuration for the Admin plugin.
type AdminConfig struct {
	// AdminRoles defines the roles that have admin access to the /admin/* endpoints.
	// Default: ["admin"]
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
	// {admin, user} roles, plus goauth's backward-compatible mapping of every AdminRoles entry
	// to the default admin role (see EffectiveRoles). When set, only these roles are used.
	Roles access.Roles

	// AdminUserIDs mirrors better-auth's `adminUserIds`: these users pass every admin permission
	// check regardless of their role.
	AdminUserIDs []string

	// AllowImpersonatingAdmins mirrors better-auth's `allowImpersonatingAdmins`. When false
	// (default), impersonating a user holding an admin role (or listed in AdminUserIDs) requires
	// the user:impersonate-admins permission.
	AllowImpersonatingAdmins bool
}

// DefaultAdminConfig returns the default configuration for the admin plugin.
func DefaultAdminConfig() AdminConfig {
	return AdminConfig{
		AdminRoles:                    []enums.Role{enums.Admin},
		DefaultRole:                   enums.User,
		ImpersonationSessionExpiresIn: 7 * 24 * time.Hour,
	}
}
