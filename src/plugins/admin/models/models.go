package models

import (
	"time"

	"github.com/better-go-auth/goauth/src/models/enums"
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
}

// DefaultAdminConfig returns the default configuration for the admin plugin.
func DefaultAdminConfig() AdminConfig {
	return AdminConfig{
		AdminRoles:                    []enums.Role{enums.Admin},
		DefaultRole:                   enums.User,
		ImpersonationSessionExpiresIn: 7 * 24 * time.Hour,
	}
}
