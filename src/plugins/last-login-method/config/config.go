// Package config holds the options of the last-login-method plugin (better-auth's LastLoginMethodOptions).
package config

import (
	"time"

	"github.com/better-go-auth/goauth/src/common/endpointhooks"
)

// DefaultCookieName is better-auth's cookie name. It is used as is (no cookie prefix, no __Secure- prefix),
// like better-auth; the cookie takes the session cookie's attributes (path, domain, Secure, SameSite) but is
// readable from JavaScript (not HttpOnly).
const DefaultCookieName = "better-auth.last_used_login_method"

// DefaultMaxAge is the cookie lifetime (better-auth's 30 days).
const DefaultMaxAge = 30 * 24 * time.Hour

// FieldLastLoginMethod is the user field written with StoreInDatabase.
const FieldLastLoginMethod = "lastLoginMethod"

// ResolveFunc is better-auth's customResolveMethod: it returns the login method of a request. ok=false falls
// back to the default resolution; ok=true with "" means "no login method" (nothing is set).
//
// In the after hook c.Path is the route path (e.g. "/callback/{id}"); in the database hooks (StoreInDatabase)
// it is the request path relative to BasePath (e.g. "/callback/google"). c.Request is always the request.
type ResolveFunc func(c *endpointhooks.Context) (method string, ok bool)

// LastLoginMethodConfig holds the options of the last-login-method plugin.
type LastLoginMethodConfig struct {
	// CookieName is the name of the cookie holding the last method (default DefaultCookieName).
	CookieName string
	// MaxAge is the cookie lifetime (default 30 days).
	MaxAge time.Duration
	// CustomResolveMethod resolves the login method before the default rules.
	CustomResolveMethod ResolveFunc
	// StoreInDatabase also stores the method in the user's lastLoginMethod field (better-auth adds the field
	// to the user schema; goauth declares it through plugins.SchemaProvider).
	StoreInDatabase bool
	// FieldName is the physical column of lastLoginMethod (better-auth's schema.user.lastLoginMethod);
	// empty = derived from the field name with the configured column case.
	FieldName string
}

// WithDefaults fills unset options with better-auth's defaults.
func (c LastLoginMethodConfig) WithDefaults() LastLoginMethodConfig {
	if c.CookieName == "" {
		c.CookieName = DefaultCookieName
	}
	if c.MaxAge <= 0 {
		c.MaxAge = DefaultMaxAge
	}
	return c
}
