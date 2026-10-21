package config

import (
	"time"

	"github.com/better-go-auth/goauth/src/config"
)

// SessionJWT configures the access and refresh JWT tokens issued by the access-token plugin.
type SessionJWT struct {
	// AccessSecret signs access tokens; defaults to a key derived from core Secret.
	AccessSecret string `koanf:"ACCESS_SECRET"`
	// RefreshSecret signs refresh tokens; defaults to a different key derived from core Secret.
	RefreshSecret string `koanf:"REFRESH_SECRET"`
	// AccessExpiresIn is the access token lifetime (default 15 minutes).
	AccessExpiresIn time.Duration
	// RefreshExpiresIn is the refresh token lifetime (default 7 days).
	RefreshExpiresIn time.Duration
	// RotateRefreshToken replaces the refresh (session) token on every /refresh (default false).
	// Turn it on to keep the session token changing across refreshes.
	RotateRefreshToken *bool
	// CheckRevocation verifies session validity in repository/DB on every request carrying an access token.
	CheckRevocation bool
}

// RotatesRefreshToken reports whether /refresh issues a new refresh token (default false).
func (j SessionJWT) RotatesRefreshToken() bool {
	return j.RotateRefreshToken != nil && *j.RotateRefreshToken
}

// DefaultUpdatableSessionFields defines the default allowed session patch fields.
var DefaultUpdatableSessionFields = []string{"deviceToken", "deviceId", "deviceName", "deviceType"}

// SessionGoAuth holds session and JWT options for the access-token plugin.
type SessionGoAuth struct {
	// SingleSession revokes a user's other sessions on every login.
	SingleSession bool
	// JWT configures the access/refresh token flow of the access-token plugin.
	JWT SessionJWT
	// UpdatableFields are the session fields (JSON names) clients may set with POST /update-session.
	// nil means DefaultUpdatableSessionFields; an empty slice allows none.
	UpdatableFields []string
}

// AccessTokenConfig holds configuration for the access-token / JWT transport plugin.
type AccessTokenConfig struct {
	// Session carries JWT expiration, secrets, and session settings.
	Session SessionGoAuth

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
		Session: SessionGoAuth{
			JWT: SessionJWT{
				AccessExpiresIn:  15 * time.Minute,
				RefreshExpiresIn: 7 * 24 * time.Hour,
			},
			UpdatableFields: DefaultUpdatableSessionFields,
		},
		Verification: config.EmailVerification{
			GoAuth: config.EmailVerificationGoAuth{
				CodeExpiresIn: 15 * time.Minute,
			},
		},
	}
}
