package config

import (
	"time"
)

// Session mirrors better-auth's `session` options; goauth-only options live in GoAuth.
type Session struct {
	// ExpiresIn is the session lifetime (default 7 days).
	ExpiresIn time.Duration
	// UpdateAge is how often the expiry slides forward (default 1 day).
	UpdateAge time.Duration
	// DisableSessionRefresh keeps expiresAt fixed regardless of UpdateAge.
	DisableSessionRefresh bool
	// StoreSessionInDatabase also writes sessions to the DB when secondary storage is set (default true).
	StoreSessionInDatabase *bool
	// PreserveSessionInDatabase keeps DB rows when a session is revoked from secondary storage.
	PreserveSessionInDatabase bool
	// FreshAge is how long after creation a session counts as fresh (default 1 day, negative disables the check).
	FreshAge time.Duration
	// DeferSessionRefresh makes GET /get-session read-only; clients POST to refresh.
	DeferSessionRefresh bool
}

// SessionGoAuth holds session options better-auth doesn't have (AuthConfig.GoAuth.Session).
type SessionGoAuth struct {
	// SingleSession revokes a user's other sessions on every login.
	SingleSession bool
	// JWT configures the access/refresh token flow of the legacy routes.
	JWT SessionJWT
	// UpdatableFields are the session fields (JSON names) clients may set with POST /update-session.
	// nil means DefaultUpdatableSessionFields; an empty slice allows none.
	UpdatableFields []string
}

// DefaultUpdatableSessionFields are goauth's client-owned device fields.
var DefaultUpdatableSessionFields = []string{"deviceToken", "deviceId", "deviceName", "deviceType"}

// SessionJWT configures the access/refresh JWTs issued by the legacy routes.
type SessionJWT struct {
	// AccessSecret signs access tokens; defaults to a key derived from Secret.
	AccessSecret string `koanf:"ACCESS_SECRET"`
	// RefreshSecret signs refresh tokens; defaults to a different key derived from Secret.
	RefreshSecret string `koanf:"REFRESH_SECRET"`
	// AccessExpiresIn is the access token lifetime (default 1 hour).
	AccessExpiresIn time.Duration
	// RefreshExpiresIn is only the default impersonation lifetime now; legacy sessions live for
	// Session.ExpiresIn and slide like better-auth sessions.
	RefreshExpiresIn time.Duration
	// RotateRefreshToken replaces the refresh (session) token on every /refresh (default true).
	// better-auth never rotates; turn it off to keep the session token stable across refreshes.
	RotateRefreshToken *bool
	// CheckRevocation looks the session up on every request that carries an access token.
	// Forced on when no secondary storage is configured, otherwise revocation cannot work.
	CheckRevocation bool
}

// StoreInDatabase reports whether sessions are persisted to the database.
func (s Session) StoreInDatabase() bool {
	return s.StoreSessionInDatabase == nil || *s.StoreSessionInDatabase
}

// RotatesRefreshToken reports whether /refresh issues a new refresh token (default true).
func (j SessionJWT) RotatesRefreshToken() bool {
	return j.RotateRefreshToken == nil || *j.RotateRefreshToken
}

type CookieCacheStrategy string

const (
	CookieCacheStrategyCompact CookieCacheStrategy = "compact"
	CookieCacheStrategyJwt     CookieCacheStrategy = "jwt"
	CookieCacheStrategyJwe     CookieCacheStrategy = "jwe"
)
