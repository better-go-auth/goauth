package config

import (
	"time"
)

type JwtVar struct {
	AccessSecret     string `koanf:"ACCESS_SECRET"`
	RefreshSecret    string `koanf:"REFRESH_SECRET"`
	AccessExpireMin  int    `koanf:"ACCESS_SECRET_EXPIRE_MIN"`
	RefreshExpireMin int    `koanf:"REFRESH_SECRET_EXPIRES_MIN"`
}

type SessionConfig struct {
	JwtVar
	// CheckRevocationInDb verifies the session row on every authenticated request.
	// Forced on when no secondary storage is configured, otherwise revocation cannot work.
	CheckRevocationInDb bool
	BlacklistPrefix     string
	RevocationPrefix    string
	// SingleSession revokes a user's other sessions on every login.
	SingleSession bool
}

// Session configures better-auth style sessions (opaque token in a signed cookie); used in compat mode.






type Session struct {
	CheckRevocationInDb bool
	BlacklistPrefix     string
	RevocationPrefix    string

	//=====================================================================================Unused currently ============================
	//
	//====================================================================
	/**
	* Expiration time for the session token. The value
	* should be in seconds.
	* @default 7 days (60 * 60 * 24 * 7)
	- this equals refresh expirations
	*/
	// ExpiresIn is the session lifetime (default 7 days).
	ExpiresIn time.Duration

	/**
	* How often the session should be refreshed. The value
	* should be in seconds.
	* If set 0 the session will be refreshed every time it is used.
	* @default 1 day (60 * 60 * 24)

	- this is like half life: ?? need to search more
	*/
	// UpdateAge is how often the expiry slides forward (default 1 day).
	UpdateAge time.Duration
	/**
	 * Disable session refresh so that the session is not updated
	 * regardless of the `updateAge` option.
	 *
	 * @default false
	 */
	 // DisableSessionRefresh keeps expiresAt fixed regardless of UpdateAge.
	DisableSessionRefresh bool

	/**
	 * By default if secondary storage is provided
	 * the session is stored in the secondary storage.
	 *
	 * Set this to true to store the session in the database
	 * as well.
	 *
	 * Reads are always done from the secondary storage.
	 *
	 * @default true
	 */
	// StoreSessionInDatabase also writes sessions to the DB when secondary storage is set (default true).
	StoreSessionInDatabase *bool
	/**
	 * By default, sessions are deleted from the database when secondary storage
	 * is provided when session is revoked.
	 *
	 * Set this to true to preserve session records in the database,
	 * even if they are deleted from the secondary storage.
	 *
	 * @default false
	 */
	 // PreserveSessionInDatabase keeps DB rows when a session is revoked from secondary storage.
	PreserveSessionInDatabase bool

	/**
	 * The age of the session to consider it fresh.
	 *
	 * This is used to check if the session is fresh
	 * for sensitive operations. (e.g. deleting an account)
	 *
	 * If the session is not fresh, the user should be prompted
	 * to sign in again.
	 *
	 * If set to 0, the session will be considered fresh every time. (⚠︎ not recommended)
	 *
	 * @default 1 day (60 * 60 * 24)
	 */
	 // FreshAge is how long after creation a session counts as fresh (default 1 day, negative disables the check).
	FreshAge time.Duration

	// DeferSessionRefresh makes GET /get-session read-only; clients POST to refresh.
	DeferSessionRefresh bool
}

// StoreInDatabase reports whether sessions are persisted to the database.
func (s Session) StoreInDatabase() bool {
	return s.StoreSessionInDatabase == nil || *s.StoreSessionInDatabase
}

type CookieCacheStrategy string

const (
	CookieCacheStrategyCompact CookieCacheStrategy = "compact"
	CookieCacheStrategyJwt     CookieCacheStrategy = "jwt"
	CookieCacheStrategyJwe     CookieCacheStrategy = "jwe"
)
