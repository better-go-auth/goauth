package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/better-go-auth/goauth/src/providers/idgen"
	"github.com/better-go-auth/goauth/src/schema"
)

const (
	DefaultAppName      = "Better Auth"
	DefaultCookiePrefix = "better-auth"
	DefaultIPv6Subnet   = 64
	SecretEnvVar        = "BETTER_AUTH_SECRET"
	AuthSecretEnvVar    = "AUTH_SECRET"
	BaseURLEnvVar       = "BETTER_AUTH_URL"
	NextBaseURLEnvVar   = "NEXT_PUBLIC_BETTER_AUTH_URL"
	MinSecretLength     = 32
	// DefaultDevSecret is better-auth's development fallback secret (DEFAULT_SECRET). It is public, so
	// Validate refuses it (and the other well-known example secrets) when running in production.
	DefaultDevSecret = "better-auth-secret-12345678901234567890"
)

// knownDevSecrets are secrets that appear in better-auth/goauth docs, examples and tests.
var knownDevSecrets = []string{
	DefaultDevSecret,
	"better-auth-secret-123456789012345678901234567890",
	"test-secret-must-be-32-chars-long!",
}

// productionEnvVars are read (in order) to decide whether the process runs in production,
// like better-auth's isProduction (NODE_ENV === "production").
var productionEnvVars = []string{"GOAUTH_ENV", "GO_ENV", "APP_ENV", "NODE_ENV"}

// IsProduction reports whether one of GOAUTH_ENV, GO_ENV, APP_ENV or NODE_ENV is "production".
func IsProduction() bool {
	for _, k := range productionEnvVars {
		if strings.EqualFold(strings.TrimSpace(os.Getenv(k)), "production") {
			return true
		}
	}
	return false
}

// IsDevSecret reports whether secret is one of the public development/example secrets.
func IsDevSecret(secret string) bool {
	for _, s := range knownDevSecrets {
		if secret == s {
			return true
		}
	}
	return false
}

// Advanced mirrors better-auth's `advanced` options.
type Advanced struct {
	// CookiePrefix prefixes every auth cookie name (default "better-auth").
	CookiePrefix string
	// UseSecureCookies forces the Secure flag on/off; nil infers it from BaseURL (https).
	UseSecureCookies      *bool
	CrossSubDomainCookies CrossSubDomainCookies
	DisableCSRFCheck      bool
	DisableOriginCheck    bool
	// Database mirrors better-auth's `advanced.database.generateId`.
	// Set GenerateID to override the default 32-char alphanumeric ID generator.
	Database  AdvancedDatabase
	IPAddress IPAddress
	// BackgroundTasks mirrors better-auth's `advanced.backgroundTasks` (non-blocking senders).
	BackgroundTasks BackgroundTasks
	// Cookies overrides the name and attributes of single auth cookies, keyed by the cookie name without
	// prefix: "session_token", "session_data", "dont_remember", "account_data", "two_factor", "state", ...
	// (better-auth's advanced.cookies).
	Cookies map[string]CookieOverride
	// DefaultCookieAttributes apply to every auth cookie, below per-cookie attributes
	// (better-auth's advanced.defaultCookieAttributes), e.g. {SameSite: "none", Secure: &yes, Partitioned: &yes}.
	DefaultCookieAttributes *CookieAttributes
	// TrustedProxyHeaders makes X-Forwarded-Host / X-Forwarded-Proto count when the base URL is derived from
	// the request (better-auth's advanced.trustedProxyHeaders). nil = trusted for a DynamicBaseURL (better-auth's
	// default there).
	TrustedProxyHeaders *bool

	GoAuth AdvancedGoAuth
}

// AdvancedDatabase mirrors better-auth's `advanced.database`.
//
// better-auth's `generateId` maps to these fields:
//
//	generateId: fn          → GenerateID: fn
//	generateId: "uuid"      → IDFormat: IDFormatUUID
//	generateId: false       → IDFormat: IDFormatDatabase (the database creates ids)
//	generateId: "serial"    → IDFormat: IDFormatSerial (auto-increment integer ids)
//	(unset)                 → IDFormat: "" = IDFormatRandom (32-char [a-zA-Z0-9])
type AdvancedDatabase struct {
	// GenerateID overrides the ID generator for new records (better-auth's generateId function).
	// It wins over IDFormat and can't be combined with IDFormatDatabase / IDFormatSerial.
	GenerateID func() string
	// IDFormat picks the record ID format: IDFormatRandom (default), IDFormatUUID, IDFormatULID (goauth's old
	// default), IDFormatDatabase or IDFormatSerial. With the last two the database creates primary keys:
	// generated DDL gives the id column a default (database) or makes it auto-increment (serial, where
	// every reference to an id is an integer column too), and goauth reads the new id back after insert.
	// Every goauth plugin stores its tables through the schema registry and works with them; third-party
	// plugins that create GORM structs with string ids of their own don't.
	IDFormat string
}

// ID formats of AdvancedDatabase.IDFormat.
const (
	IDFormatRandom   = string(idgen.FormatRandom)
	IDFormatUUID     = string(idgen.FormatUUID)
	IDFormatULID     = string(idgen.FormatULID)
	IDFormatDatabase = "database"
	IDFormatSerial   = "serial"
)

// IDStrategy returns who creates record ids: schema.IDDatabase / schema.IDSerial for those formats,
// schema.IDApplication otherwise.
func (d AdvancedDatabase) IDStrategy() schema.IDStrategy {
	switch strings.ToLower(d.IDFormat) {
	case IDFormatDatabase:
		return schema.IDDatabase
	case IDFormatSerial:
		return schema.IDSerial
	}
	return schema.IDApplication
}

// IDGenerator returns the generator for new record IDs: GenerateID when set, else the IDFormat generator.
// When the database creates ids (IDFormatDatabase / IDFormatSerial) it returns a generator of empty IDs:
// records are created without an id and the adapter reads the database's id back.
func (d AdvancedDatabase) IDGenerator() (func() string, error) {
	if d.IDStrategy().DatabaseGenerated() {
		if d.GenerateID != nil {
			return nil, fmt.Errorf("idgen: GenerateID can't be combined with IDFormat %q (the database creates ids)", d.IDFormat)
		}
		return func() string { return "" }, nil
	}
	if d.GenerateID != nil {
		return d.GenerateID, nil
	}
	return idgen.ForFormat(idgen.Format(d.IDFormat))
}

// AdvancedGoAuth holds advanced options better-auth doesn't have.
func WithStoreInDatabase(s *Session, v bool) {
	s.StoreSessionInDatabase = v
	s.StoreSessionInDatabaseSet = true
}

type AdvancedGoAuth struct {
	// OverrideHumaErrors formats every Huma error in the process (including host routes) as {"code","message"}.
	// By default only goauth routes use that format.
	OverrideHumaErrors bool
	// RequireSecret makes a missing Secret ($BETTER_AUTH_SECRET / $AUTH_SECRET) a startup error everywhere.
	// Default false: like better-auth, development falls back to the public DefaultDevSecret (with a
	// warning) and only production refuses it.
	RequireSecret bool
	// ErrorRequestID adds the request ID of internal (500) errors to the response: a requestId field in
	// the {code, message} body and an X-Request-Id header. Default false: the body is better-auth's
	// {code, message}; the cause and the request ID are only logged.
	ErrorRequestID bool
}

type CrossSubDomainCookies struct {
	Enabled bool
	// Domain defaults to the BaseURL hostname when empty.
	Domain string
}

type IPAddress struct {
	// Headers are checked in order to resolve the client IP.
	Headers         []string
	DisableTracking bool
	// IPv6Subnet groups IPv6 addresses by prefix length (default 64).
	IPv6Subnet int
}

// SecureCookies reports whether auth cookies must carry the Secure flag.
// Prefer SecureCookiesCached after SetDefaults has been called.
func (opts *AuthConfig) SecureCookies() bool {
	if opts.Advanced.UseSecureCookies != nil {
		return *opts.Advanced.UseSecureCookies
	}
	// a dynamic base URL decides by its protocol, else by the environment (better-auth's createCookieGetter)
	if d := opts.DynamicBaseURL; d != nil {
		switch d.Protocol {
		case "https":
			return true
		case "http":
			return false
		}
		return IsProduction()
	}
	return strings.HasPrefix(strings.ToLower(opts.BaseURL), "https://")
}

// CookieDomain returns the Domain attribute for auth cookies ("" = host-only).
func (opts *AuthConfig) SecureCookiesCached() bool {
	if opts.cachedSecure != nil {
		return *opts.cachedSecure
	}
	return opts.SecureCookies()
}

func (opts *AuthConfig) CookieDomain() string {
	if !opts.Advanced.CrossSubDomainCookies.Enabled {
		return ""
	}
	if opts.Advanced.CrossSubDomainCookies.Domain != "" {
		return opts.Advanced.CrossSubDomainCookies.Domain
	}
	u, err := url.Parse(opts.BaseURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func (opts *AuthConfig) CookieDomainCached() string {
	if opts.cachedDomainOnce {
		return opts.cachedCookieDomain
	}
	return opts.CookieDomain()
}
