package config

import (
	"time"

	"github.com/better-go-auth/goauth/src/config"
)

// AccessTokenConfig holds configuration for the legacy access-token / JWT transport plugin.
type AccessTokenConfig struct {
	// Session carries JWT expiration, secrets, and session settings.
	Session config.SessionGoAuth

	// Verification carries email verification settings (code sender, generator, expiry).
	Verification config.EmailVerification

	// BasePath is the route prefix (e.g. "/api/auth"). Default: "/api/auth".
	BasePath string

	// CookieSecure sets the Secure attribute on cookies.
	CookieSecure bool

	// CookieDomain sets the Domain attribute on cookies.
	CookieDomain string
}

// DefaultAccessTokenConfig returns sensible defaults for the access-token plugin.
func DefaultAccessTokenConfig() AccessTokenConfig {
	return AccessTokenConfig{
		BasePath: "/api/auth",
		Session: config.SessionGoAuth{
			JWT: config.SessionJWT{
				AccessExpiresIn:  15 * time.Minute,
				RefreshExpiresIn: 7 * 24 * time.Hour,
			},
		},
		Verification: config.EmailVerification{
			GoAuth: config.EmailVerificationGoAuth{
				CodeExpiresIn: 15 * time.Minute,
			},
		},
	}
}
