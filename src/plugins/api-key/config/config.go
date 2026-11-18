// Package config holds the options of the api-key plugin (@better-auth/api-key 1.6.16's
// ApiKeyConfigurationOptions and ApiKeyOptions).
package config

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/better-go-auth/goauth/src/providers/access"
)

// Defaults of better-auth's apiKey() plugin.
const (
	// DefaultConfigID is the configId of keys created with the default configuration.
	DefaultConfigID = "default"
	// DefaultHeader is the request header the API key is read from.
	DefaultHeader = "x-api-key"
	// DefaultKeyLength is the number of random characters of a generated key (the prefix not included).
	DefaultKeyLength = 64
	// DefaultMaximumPrefixLength / DefaultMinimumPrefixLength bound a custom prefix.
	DefaultMaximumPrefixLength = 32
	DefaultMinimumPrefixLength = 1
	// DefaultMaximumNameLength / DefaultMinimumNameLength bound the key name.
	DefaultMaximumNameLength = 32
	DefaultMinimumNameLength = 1
	// DefaultRateLimitTimeWindow is the per-key rate-limit window (one day).
	DefaultRateLimitTimeWindow = 24 * time.Hour
	// DefaultRateLimitMaxRequests is the number of requests allowed per window.
	DefaultRateLimitMaxRequests = 10
	// DefaultMaxExpiresInDays / DefaultMinExpiresInDays bound expiresIn (in days).
	DefaultMaxExpiresInDays = 365
	DefaultMinExpiresInDays = 1
	// DefaultStartingCharactersLength is how many leading characters of a key are stored in `start`.
	DefaultStartingCharactersLength = 6
)

// References selects what owns an API key (better-auth's `references`).
type References string

const (
	// ReferencesUser makes keys belong to a user (referenceId = user id). Default.
	ReferencesUser References = "user"
	// ReferencesOrganization makes keys belong to an organization (referenceId = organization id); the
	// organization plugin decides who may manage them (resource "apiKey", actions create/read/update/delete).
	ReferencesOrganization References = "organization"
)

// StorageMode selects where keys are stored (better-auth's `storage`).
type StorageMode string

const (
	// StorageDatabase stores keys in the apikey table. Default.
	StorageDatabase StorageMode = "database"
	// StorageSecondary stores keys in the secondary storage (GoAuthOptions.SecondaryStorage or
	// Configuration.CustomStorage) under better-auth's keys, so a TypeScript server can share them.
	StorageSecondary StorageMode = "secondary-storage"
)

// KeyStorage is a custom key-value store for API keys (better-auth's `customStorage`); it takes
// precedence over the secondary storage. Values are better-auth's JSON strings.
type KeyStorage interface {
	// Get returns the value of key; ok is false when the key does not exist.
	Get(ctx context.Context, key string) (value string, ok bool, err error)
	// Set stores value under key; ttl <= 0 means no expiry.
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	// Delete removes key (a missing key is not an error).
	Delete(ctx context.Context, key string) error
}

// KeyExpiration customizes key expiry (better-auth's `keyExpiration`).
type KeyExpiration struct {
	// DefaultExpiresIn is the lifetime of keys created without expiresIn (0 = keys do not expire).
	// better-auth documents milliseconds but applies the value as seconds; goauth takes a Duration.
	DefaultExpiresIn time.Duration
	// DisableCustomExpiresTime rejects expiresIn from create / update with KEY_DISABLED_EXPIRATION.
	DisableCustomExpiresTime bool
	// MinExpiresIn is the smallest expiresIn accepted, in days (nil = 1).
	MinExpiresIn *float64
	// MaxExpiresIn is the largest expiresIn accepted, in days (nil = 365).
	MaxExpiresIn *float64
}

// RateLimit holds the per-key rate-limit defaults (better-auth's `rateLimit`).
type RateLimit struct {
	// Enabled turns per-key rate limiting on (nil = true). false skips the check for every key.
	Enabled *bool
	// TimeWindow is the window in which requests are counted (0 = one day).
	TimeWindow time.Duration
	// MaxRequests is the number of requests allowed per window (nil = 10).
	MaxRequests *int
}

// StartingCharacters controls the `start` column (better-auth's `startingCharactersConfig`).
type StartingCharacters struct {
	// ShouldStore stores the first CharactersLength characters of the key (prefix included) in `start`
	// (nil = true); false stores null.
	ShouldStore *bool
	// CharactersLength is the number of characters stored (0 = 6).
	CharactersLength int
}

// Permissions holds the default permissions of new keys (better-auth's `permissions`).
type Permissions struct {
	// DefaultPermissions are given to keys created without permissions.
	DefaultPermissions access.Statements
	// DefaultPermissionsFunc computes them per owner (referenceId); it wins over DefaultPermissions.
	DefaultPermissionsFunc func(ctx context.Context, referenceID string) (access.Statements, error)
}

// Configuration is one set of API key options (better-auth's ApiKeyConfigurationOptions). A plugin with
// several configurations tells them apart with ConfigID; keys remember the configuration they were created
// with (`configId` column).
type Configuration struct {
	// ConfigID names the configuration. Required (and unique) when the plugin has several configurations;
	// "" or "default" is the default configuration.
	ConfigID string
	// APIKeyHeaders are the request headers the key is read from, in order (default ["x-api-key"]).
	APIKeyHeaders []string
	// DisableKeyHashing stores keys in plain text instead of their SHA-256 hash (not recommended).
	DisableKeyHashing bool
	// CustomAPIKeyGetter reads the key from a request instead of APIKeyHeaders ("" = no key).
	CustomAPIKeyGetter func(r *http.Request) string
	// CustomAPIKeyValidator is an extra check of a presented key; false rejects it.
	CustomAPIKeyValidator func(ctx context.Context, key string) (bool, error)
	// CustomKeyGenerator replaces the default generator (prefix + length random letters).
	CustomKeyGenerator func(ctx context.Context, length int, prefix string) (string, error)
	// StartingCharactersConfig controls the stored `start` of a key.
	StartingCharactersConfig StartingCharacters
	// DefaultKeyLength is the number of random characters of a generated key (0 = 64). Keys presented in
	// a request header that are shorter are rejected with INVALID_API_KEY.
	DefaultKeyLength int
	// DefaultPrefix is prepended to generated keys (e.g. "goauth_").
	DefaultPrefix string
	// MaximumPrefixLength / MinimumPrefixLength bound a custom prefix (0 = 32 / 1).
	MaximumPrefixLength int
	MinimumPrefixLength int
	// RequireName makes the name mandatory on create (NAME_REQUIRED).
	RequireName bool
	// MaximumNameLength / MinimumNameLength bound the name (0 = 32 / 1).
	MaximumNameLength int
	MinimumNameLength int
	// EnableMetadata allows the metadata object on create / update.
	EnableMetadata bool
	// KeyExpiration customizes expiry.
	KeyExpiration KeyExpiration
	// RateLimit holds the per-key rate-limit defaults.
	RateLimit RateLimit
	// EnableSessionForAPIKeys makes a request with a valid API key (APIKeyHeaders / CustomAPIKeyGetter)
	// authenticated as the key's owner on every goauth route: a session is mocked for the request (never
	// stored), GET /get-session returns it. Only for keys of user-referenced configurations.
	EnableSessionForAPIKeys bool
	// Permissions holds the default permissions of new keys.
	Permissions Permissions
	// Storage is StorageDatabase (default) or StorageSecondary.
	Storage StorageMode
	// FallbackToDatabase (with StorageSecondary) writes keys to the database too and reads the database when
	// the secondary storage misses, caching what it found.
	FallbackToDatabase bool
	// CustomStorage replaces the secondary storage for this configuration.
	CustomStorage KeyStorage
	// DeferUpdates runs non-critical writes (usage counters, timestamps, deleting expired keys) through
	// AuthConfig.Advanced.BackgroundTasks.Handler after the response; the response carries the optimistic
	// values.
	DeferUpdates bool
	// References is ReferencesUser (default) or ReferencesOrganization.
	References References
}

// SchemaOptions renames the apikey table and its columns (better-auth's `schema` option).
type SchemaOptions struct {
	// ModelName is the table name (default "apikey").
	ModelName string
	// Fields maps logical field names (e.g. "referenceId") to column names.
	Fields map[string]string
}

// WithDefaults returns c with better-auth's defaults filled in.
func (c Configuration) WithDefaults() Configuration {
	// Step 1: headers, lengths and the stored prefix
	if len(c.APIKeyHeaders) == 0 {
		c.APIKeyHeaders = []string{DefaultHeader}
	}
	if c.DefaultKeyLength <= 0 {
		c.DefaultKeyLength = DefaultKeyLength
	}
	if c.MaximumPrefixLength <= 0 {
		c.MaximumPrefixLength = DefaultMaximumPrefixLength
	}
	if c.MinimumPrefixLength <= 0 {
		c.MinimumPrefixLength = DefaultMinimumPrefixLength
	}
	if c.MaximumNameLength <= 0 {
		c.MaximumNameLength = DefaultMaximumNameLength
	}
	if c.MinimumNameLength <= 0 {
		c.MinimumNameLength = DefaultMinimumNameLength
	}
	// Step 2: storage and ownership
	if c.Storage == "" {
		c.Storage = StorageDatabase
	}
	if c.References == "" {
		c.References = ReferencesUser
	}
	// Step 3: rate limiting
	if c.RateLimit.Enabled == nil {
		on := true
		c.RateLimit.Enabled = &on
	}
	if c.RateLimit.TimeWindow <= 0 {
		c.RateLimit.TimeWindow = DefaultRateLimitTimeWindow
	}
	if c.RateLimit.MaxRequests == nil {
		n := DefaultRateLimitMaxRequests
		c.RateLimit.MaxRequests = &n
	}
	// Step 4: expiry bounds (days)
	if c.KeyExpiration.MaxExpiresIn == nil {
		v := float64(DefaultMaxExpiresInDays)
		c.KeyExpiration.MaxExpiresIn = &v
	}
	if c.KeyExpiration.MinExpiresIn == nil {
		v := float64(DefaultMinExpiresInDays)
		c.KeyExpiration.MinExpiresIn = &v
	}
	// Step 5: the stored start of the key
	if c.StartingCharactersConfig.ShouldStore == nil {
		on := true
		c.StartingCharactersConfig.ShouldStore = &on
	}
	if c.StartingCharactersConfig.CharactersLength <= 0 {
		c.StartingCharactersConfig.CharactersLength = DefaultStartingCharactersLength
	}
	return c
}

// IsDefault reports whether the configuration is the default one ("" or "default").
func (c Configuration) IsDefault() bool { return IsDefaultConfigID(c.ConfigID) }

// RateLimitEnabled reports whether per-key rate limiting is on.
func (c Configuration) RateLimitEnabled() bool {
	return c.RateLimit.Enabled == nil || *c.RateLimit.Enabled
}

// IsDefaultConfigID reports whether id names the default configuration ("" or "default"); keys created
// before the configId column existed have none.
func IsDefaultConfigID(id string) bool { return id == "" || id == DefaultConfigID }

// ConfigIDMatches reports whether a key's configId matches the expected one ("" and "default" are equal).
func ConfigIDMatches(keyConfigID, expected string) bool {
	if IsDefaultConfigID(keyConfigID) && IsDefaultConfigID(expected) {
		return true
	}
	return keyConfigID == expected
}

// ValidateConfigurations mirrors better-auth's checks of a configuration array: every configuration has a
// configId and the ids are unique, and the options are consistent.
func ValidateConfigurations(cfgs []Configuration) error {
	// Step 1: several configurations need distinct ids (better-auth throws a BetterAuthError)
	if len(cfgs) > 1 {
		seen := map[string]bool{}
		for _, c := range cfgs {
			if c.ConfigID == "" {
				return errors.New("api-key: configId is required for each API key configuration in the api-key plugin")
			}
			if seen[c.ConfigID] {
				return errors.New("api-key: configId must be unique for each API key configuration in the api-key plugin")
			}
			seen[c.ConfigID] = true
		}
	}
	// Step 2: option values goauth cannot run with
	for _, c := range cfgs {
		switch c.Storage {
		case "", StorageDatabase, StorageSecondary:
		default:
			return fmt.Errorf("api-key: unknown storage %q (use %q or %q)", c.Storage, StorageDatabase, StorageSecondary)
		}
		switch c.References {
		case "", ReferencesUser, ReferencesOrganization:
		default:
			return fmt.Errorf("api-key: unknown references %q (use %q or %q)", c.References, ReferencesUser, ReferencesOrganization)
		}
	}
	return nil
}
