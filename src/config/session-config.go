package config

import (
	"time"

	"github.com/better-go-auth/goauth/src/schema"
)

type CookieCacheStrategy string

const (
	CookieCacheStrategyCompact CookieCacheStrategy = "compact"
	CookieCacheStrategyJwt     CookieCacheStrategy = "jwt"
	CookieCacheStrategyJwe     CookieCacheStrategy = "jwe"
)

// CookieCacheRefresh controls automatic stateless refresh before expiry.
type CookieCacheRefresh struct {
	// Enabled controls whether automatic stateless refresh is enabled.
	Enabled bool `json:"enabled,omitempty"`
	// UpdateAge is the time window before expiry when the cache should refresh.
	// For example, if MaxAge is 5m and UpdateAge is 1m, the cache will refresh
	// when it has 1m left before expiry. Defaults to 20% of MaxAge.
	UpdateAge time.Duration `json:"updateAge,omitempty"`
}

// CookieCache configures caching session data in the session_data cookie.
type CookieCache struct {
	// Enabled enables session caching in the session_data cookie (default false).
	Enabled *bool `json:"enabled,omitempty"`
	// MaxAge is the lifetime of the session_data cookie (default 5 minutes).
	MaxAge time.Duration `json:"maxAge,omitempty"`
	// Strategy controls encoding/crypto: "compact" (HMAC), "jwt" (JWT), "jwe" (encrypted). Default: "compact".
	Strategy CookieCacheStrategy `json:"strategy,omitempty"`
	// RefreshCache controls stateless refresh behavior before cache expiry.
	RefreshCache *CookieCacheRefresh `json:"refreshCache,omitempty"`
	// Version of the cookie cache; invalidates older cookie caches when changed (default "1").
	Version string `json:"version,omitempty"`
}

// IsEnabled reports whether cookie caching is enabled.
func (c *CookieCache) IsEnabled() bool {
	return c != nil && c.Enabled != nil && *c.Enabled
}

// EffectiveMaxAge returns the configured MaxAge, or default 5 minutes.
func (c *CookieCache) EffectiveMaxAge() time.Duration {
	if c != nil && c.MaxAge > 0 {
		return c.MaxAge
	}
	return 5 * time.Minute
}

// EffectiveStrategy returns the configured strategy, or default compact.
func (c *CookieCache) EffectiveStrategy() CookieCacheStrategy {
	if c != nil && c.Strategy != "" {
		return c.Strategy
	}
	return CookieCacheStrategyCompact
}

// EffectiveVersion returns the configured cache version, or default "1".
func (c *CookieCache) EffectiveVersion() string {
	if c != nil && c.Version != "" {
		return c.Version
	}
	return "1"
}

// IsRefreshEnabled reports whether stateless refresh is configured.
func (c *CookieCache) IsRefreshEnabled() bool {
	if c == nil || c.RefreshCache == nil {
		return false
	}
	return c.RefreshCache.Enabled || c.RefreshCache.UpdateAge > 0
}

// RefreshUpdateAge returns the threshold duration before expiry to trigger refresh.
func (c *CookieCache) RefreshUpdateAge() time.Duration {
	if c == nil || c.RefreshCache == nil {
		return 0
	}
	if c.RefreshCache.UpdateAge > 0 {
		return c.RefreshCache.UpdateAge
	}
	return c.EffectiveMaxAge() / 5 // Default 20% of MaxAge
}

// Session mirrors better-auth's `session` options; goauth-only options live in GoAuth.
type Session struct {
	// ExpiresIn is the session lifetime (default 7 days).
	ExpiresIn time.Duration
	// UpdateAge is how often the expiry slides forward (default 1 day).
	UpdateAge time.Duration
	// DisableSessionRefresh keeps expiresAt fixed regardless of UpdateAge.
	DisableSessionRefresh bool
	// StoreSessionInDatabase writes sessions to the DB when secondary storage is set (default true).
	StoreSessionInDatabase bool
	// StoreSessionInDatabaseSet is true when StoreSessionInDatabase was explicitly set (so false survives SetDefaults).
	StoreSessionInDatabaseSet bool
	// PreserveSessionInDatabase keeps DB rows when a session is revoked from secondary storage.
	PreserveSessionInDatabase bool
	// FreshAge is how long after creation a session counts as fresh (default 1 day, negative disables the check).
	FreshAge time.Duration
	// DeferSessionRefresh makes GET /get-session read-only; clients POST to refresh.
	DeferSessionRefresh bool

	// CookieCache configures stateless session caching in the session_data cookie.
	CookieCache *CookieCache

	// ModelName renames the session table (better-auth's session.modelName). It wins over GoAuth.TableNames.
	ModelName string
	// Fields renames session columns: field name → column name, used as is (better-auth's session.fields).
	Fields map[string]string
	// AdditionalFields adds session fields stored in real columns (better-auth's session.additionalFields).
	AdditionalFields map[string]schema.Field

	// GoAuth holds goauth-only session extensions (SingleSession, UpdatableFields).
	GoAuth SessionGoAuth
}

// SessionGoAuth holds session options for GoAuth (Session.GoAuth).
type SessionGoAuth struct {
	// SingleSession revokes a user's other sessions on every login.
	SingleSession bool
	// UpdatableFields are goauth's own device fields (JSON names: deviceToken, deviceId, deviceName,
	// deviceType) clients may set with POST /update-session. nil means DefaultUpdatableSessionFields; an empty
	// slice allows none. Session.AdditionalFields and plugin fields follow the schema instead (their `Input`
	// attribute), like better-auth's parseSessionInput.
	UpdatableFields []string
}

// DefaultUpdatableSessionFields are goauth's client-owned device fields.
var DefaultUpdatableSessionFields = []string{"deviceToken", "deviceId", "deviceName", "deviceType"}

// StoreInDatabase reports whether sessions are persisted to the database.
func (s Session) StoreInDatabase() bool {
	return s.StoreSessionInDatabase
}

type SessionPatch struct {
	ActiveOrganizationID   *string `json:"activeOrganizationId,omitempty"`
	ActiveOrganizationRole *string `json:"activeOrganizationRole,omitempty"`
	ActiveOrganizationType *string `json:"activeOrganizationType,omitempty"`
	ActiveTeamID           *string `json:"activeTeamId,omitempty"`
	DeviceToken            *string `json:"deviceToken,omitempty"`
	DeviceID               *string `json:"deviceId,omitempty"`
	DeviceName             *string `json:"deviceName,omitempty"`
	DeviceType             *string `json:"deviceType,omitempty"`
}

// ToMap converts SessionPatch to the map form used by UpdateSession.
func (sp SessionPatch) ToMap() map[string]any {
	m := map[string]any{}
	if sp.ActiveOrganizationID != nil {
		m["ActiveOrganizationID"] = sp.ActiveOrganizationID
	}
	if sp.ActiveOrganizationRole != nil {
		m["ActiveOrganizationRole"] = sp.ActiveOrganizationRole
	}
	if sp.ActiveOrganizationType != nil {
		m["ActiveOrganizationType"] = sp.ActiveOrganizationType
	}
	if sp.ActiveTeamID != nil {
		m["ActiveTeamID"] = sp.ActiveTeamID
	}
	if sp.DeviceToken != nil {
		m["DeviceToken"] = *sp.DeviceToken
	}
	if sp.DeviceID != nil {
		m["DeviceID"] = sp.DeviceID
	}
	if sp.DeviceName != nil {
		m["DeviceName"] = sp.DeviceName
	}
	if sp.DeviceType != nil {
		m["DeviceType"] = sp.DeviceType
	}
	return m
}
