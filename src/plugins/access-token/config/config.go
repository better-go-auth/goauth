package config

import (
	"time"

	"github.com/better-go-auth/goauth/src/config"
)

// SessionJWT configures the access token JWT issued by the access-token plugin.
// The session.token itself serves as the refresh token (governed by core Session config).
type SessionJWT struct {
	// AccessSecret signs access tokens; defaults to a key derived from core Secret.
	AccessSecret string `koanf:"ACCESS_SECRET"`
	// AccessExpiresIn is the access token lifetime (default 15 minutes).
	AccessExpiresIn time.Duration

	// RotateSessionToken replaces the refresh (session) token on every /refresh (default false).
	// Turn it on to keep the session token changing across refreshes.
	RotateSessionToken *bool
	// CheckRevocation verifies session validity in repository/DB on every request carrying an access token.
	CheckRevocation bool
}

// RotatesRefreshToken reports whether /refresh issues a new refresh token (default false).
func (j SessionJWT) RotatesRefreshToken() bool {
	return j.RotateSessionToken != nil && *j.RotateSessionToken
}

// SessionGoAuth holds session and JWT options for the access-token plugin.
// It embeds core config.SessionGoAuth (SingleSession, UpdatableFields) and adds access token JWT settings.
type SessionGoAuth struct {
	config.SessionGoAuth
	// JWT configures the access/refresh token flow of the access-token plugin.
	JWT SessionJWT
}

// AccessTokenConfig holds configuration for the access-token / JWT transport plugin.
type AccessTokenConfig struct {
	// Session carries JWT expiration, secrets, and session settings.
	Session SessionGoAuth
	// AutoRegisterMiddleware controls whether the access token middleware is automatically registered
	// as a global middleware on the Huma API. When false (default), the middleware is only applied to routes
	// that explicitly include it via Plugin.AuthMiddleware(), keeping core Better Auth endpoints isolated.
	AutoRegisterMiddleware bool
}

// DefaultAccessTokenConfig returns sensible defaults for the access-token plugin.
func DefaultAccessTokenConfig() AccessTokenConfig {
	return AccessTokenConfig{
		Session: SessionGoAuth{
			SessionGoAuth: config.SessionGoAuth{
				UpdatableFields: config.DefaultUpdatableSessionFields,
			},
			JWT: SessionJWT{
				AccessExpiresIn: 15 * time.Minute,
			},
		},
	}
}
