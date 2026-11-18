package config

import (
	"net/url"
	"os"
	"strings"

	"github.com/better-go-auth/goauth/src/providers/idgen"
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

	GoAuth AdvancedGoAuth
}

// AdvancedDatabase mirrors better-auth's `advanced.database`.
type AdvancedDatabase struct {
	// GenerateID overrides the ID generator for new records (better-auth's generateId function).
	// It wins over IDFormat.
	GenerateID func() string
	// IDFormat picks a built-in ID format: "random" (default, better-auth's 32-char [a-zA-Z0-9] IDs),
	// "uuid" (better-auth's generateId: "uuid") or "ulid" (26-char sortable IDs, goauth's old default).
	IDFormat string
}

// IDGenerator returns the generator for new record IDs: GenerateID when set, else the IDFormat generator.
func (d AdvancedDatabase) IDGenerator() (func() string, error) {
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
