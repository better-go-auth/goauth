package config

import (
	"time"

	"github.com/better-go-auth/goauth/src/providers/ratelimit"
)

// RateLimitOptions mirrors better-auth's `rateLimit` options. One limiter covers every core and plugin
// route (see package ratelimit for the rule resolution order).
type RateLimitOptions struct {
	// Enabled turns the limiter on or off. nil (default) enables it in production only, like better-auth
	// (`enabled ?? isProduction`; production = GOAUTH_ENV / GO_ENV / APP_ENV / NODE_ENV is "production").
	Enabled *bool
	// Window is the default window (default 10s).
	Window time.Duration
	// Max is the default number of requests per window (default 100).
	Max int
	// Storage is "memory", "secondary-storage" or "database" (default: "secondary-storage" when
	// GoAuthOptions.SecondaryStorage is set, else "memory"). "database" stores records in better-auth's
	// rateLimit table (key, count, lastRequest in Unix ms) through the storage adapter; the table is part
	// of the schema registry (and created by the migrator) only with this storage.
	Storage string
	// ModelName renames the rateLimit table (better-auth's rateLimit.modelName).
	ModelName string
	// Fields renames rateLimit columns: field name (key, count, lastRequest) → column (better-auth's
	// rateLimit.fields).
	Fields map[string]string
	// CustomRules override the rule per path: exact paths relative to BasePath ("/sign-in/email") or wildcard
	// patterns ("/sign-in/*", "/organization/**"). A rule can set Window/Max, be Disabled, or Resolve per
	// request (better-auth's customRules: rule | false | function).
	CustomRules map[string]ratelimit.CustomRule
	// CustomStorage replaces Storage (better-auth's customStorage).
	CustomStorage ratelimit.Storage
}

// IsEnabled resolves Enabled: an explicit value wins, otherwise the limiter runs in production only.
func (o RateLimitOptions) IsEnabled() bool {
	if o.Enabled != nil {
		return *o.Enabled
	}
	return IsProduction()
}
