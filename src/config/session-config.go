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
}

// SessionGoAuth holds session options for GoAuth (AuthConfig.GoAuth.Session).
type SessionGoAuth struct {
	// SingleSession revokes a user's other sessions on every login.
	SingleSession bool
	// UpdatableFields are the session fields (JSON names) clients may set with POST /update-session.
	// nil means DefaultUpdatableSessionFields; an empty slice allows none.
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
	ActiveTeamID           *string `json:"activeTeamId,omitempty"`
	DeviceToken            *string `json:"deviceToken,omitempty"`
	DeviceID               *string `json:"deviceId,omitempty"`
	DeviceName             *string `json:"deviceName,omitempty"`
	DeviceType             *string `json:"deviceType,omitempty"`
}

// ToMap converts SessionPatch to the map form used by UpdateSession.
func (sp SessionPatch) ToMap() map[string]any {
	m := map[string]any{}
	if sp.ActiveOrganizationID != nil { m["ActiveOrganizationID"] = sp.ActiveOrganizationID }
	if sp.ActiveOrganizationRole != nil { m["ActiveOrganizationRole"] = sp.ActiveOrganizationRole }
	if sp.ActiveTeamID != nil { m["ActiveTeamID"] = sp.ActiveTeamID }
	if sp.DeviceToken != nil { m["DeviceToken"] = *sp.DeviceToken }
	if sp.DeviceID != nil { m["DeviceID"] = sp.DeviceID }
	if sp.DeviceName != nil { m["DeviceName"] = sp.DeviceName }
	if sp.DeviceType != nil { m["DeviceType"] = sp.DeviceType }
	return m
}

type CookieCacheStrategy string

const (
	CookieCacheStrategyCompact CookieCacheStrategy = "compact"
	CookieCacheStrategyJwt     CookieCacheStrategy = "jwt"
	CookieCacheStrategyJwe     CookieCacheStrategy = "jwe"
)
