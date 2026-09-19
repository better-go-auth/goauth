package config

import (
	"time"

	conf "github.com/birukbelay/gocmn/src/config"
)

type SessionConfig struct {
	conf.JwtVar
	CheckRevocationInDb bool
	BlacklistPrefix     string
	RevocationPrefix    string
}
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
	ExpiresIn time.Duration

	/**
	* How often the session should be refreshed. The value
	* should be in seconds.
	* If set 0 the session will be refreshed every time it is used.
	* @default 1 day (60 * 60 * 24)

	- this is like half life
	*/
	UpdateAge time.Duration
	/**
	 * Disable session refresh so that the session is not updated
	 * regardless of the `updateAge` option.
	 *
	 * @default false
	 */
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
	StoreSessionInDatabase bool
	/**
	 * By default, sessions are deleted from the database when secondary storage
	 * is provided when session is revoked.
	 *
	 * Set this to true to preserve session records in the database,
	 * even if they are deleted from the secondary storage.
	 *
	 * @default false
	 */
	// PreserveSessionInDatabase bool

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
	FreshAge time.Duration
}

type CookieCacheStrategy string

const (
	CookieCacheStrategyCompact CookieCacheStrategy = "compact"
	CookieCacheStrategyJwt     CookieCacheStrategy = "jwt"
	CookieCacheStrategyJwe     CookieCacheStrategy = "jwe"
)
