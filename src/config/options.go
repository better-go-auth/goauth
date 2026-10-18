package config

import (
	"net/url"
	"strings"
)

// Mode selects which API surface goauth exposes.
type Mode string

const (
	// ModeLegacy keeps the original goauth routes and JWT access/refresh flow.
	ModeLegacy Mode = "legacy"
	// ModeCompat targets wire compatibility with better-auth (see _docs/README.md).
	ModeCompat Mode = "compat"
)

const (
	DefaultAppName      = "Better Auth"
	DefaultCookiePrefix = "better-auth"
	DefaultIPv6Subnet   = 64
	SecretEnvVar        = "BETTER_AUTH_SECRET"
	MinSecretLength     = 32
)

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
	Database AdvancedDatabase
	IPAddress  IPAddress

	GoAuth AdvancedGoAuth
}

// AdvancedDatabase mirrors better-auth's `advanced.database`.
type AdvancedDatabase struct {
	// GenerateID overrides the default ID generator for new records.
	GenerateID func() string
}

// AdvancedGoAuth holds advanced options better-auth doesn't have.
func WithStoreInDatabase(s *Session, v bool) { s.StoreSessionInDatabase = v; s.StoreSessionInDatabaseSet = true }

type AdvancedGoAuth struct {
	// OverrideHumaErrors formats every Huma error in the process (including host routes) as {"code","message"}.
	// By default only goauth routes use that format.
	OverrideHumaErrors bool
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
