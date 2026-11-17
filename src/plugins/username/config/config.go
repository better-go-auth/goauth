// Package config holds the options of the username plugin (better-auth's UsernameOptions).
package config

import "strings"

// Defaults mirror better-auth's username() plugin.
const (
	DefaultMinUsernameLength = 3
	DefaultMaxUsernameLength = 30
)

// Validation orders (better-auth's validationOrder values).
const (
	// PreNormalization validates the value as sent (default).
	PreNormalization = "pre-normalization"
	// PostNormalization validates the normalized value.
	PostNormalization = "post-normalization"
)

// ValidationOrder selects whether validators see the raw or the normalized value.
type ValidationOrder struct {
	// Username is PreNormalization (default) or PostNormalization.
	Username string
	// DisplayUsername is PreNormalization (default) or PostNormalization.
	DisplayUsername string
}

// ValidatorFunc reports whether a (display) username is acceptable.
type ValidatorFunc func(value string) bool

// NormalizerFunc rewrites a (display) username before it is stored or looked up.
type NormalizerFunc func(value string) string

// UsernameConfig mirrors better-auth's username() options.
type UsernameConfig struct {
	// MinUsernameLength is the minimum username length (default 3).
	MinUsernameLength int
	// MaxUsernameLength is the maximum username length (default 30).
	MaxUsernameLength int
	// UsernameValidator replaces the default check (letters, digits, "_" and "." only).
	UsernameValidator ValidatorFunc
	// DisplayUsernameValidator checks display usernames (no check by default).
	DisplayUsernameValidator ValidatorFunc
	// UsernameNormalization replaces the default normalization (lowercase).
	UsernameNormalization NormalizerFunc
	// DisableUsernameNormalization stores usernames as sent (better-auth's usernameNormalization: false).
	DisableUsernameNormalization bool
	// DisplayUsernameNormalization normalizes display usernames (stored as sent by default).
	DisplayUsernameNormalization NormalizerFunc
	// ValidationOrder selects whether validators see raw or normalized values.
	ValidationOrder ValidationOrder
}

// WithDefaults returns cfg with better-auth's defaults filled in.
func (cfg UsernameConfig) WithDefaults() UsernameConfig {
	// Step 1: length bounds (better-auth: options.minUsernameLength || 3, options.maxUsernameLength || 30)
	if cfg.MinUsernameLength <= 0 {
		cfg.MinUsernameLength = DefaultMinUsernameLength
	}
	if cfg.MaxUsernameLength <= 0 {
		cfg.MaxUsernameLength = DefaultMaxUsernameLength
	}
	// Step 2: default validator /^[a-zA-Z0-9_.]+$/
	if cfg.UsernameValidator == nil {
		cfg.UsernameValidator = DefaultUsernameValidator
	}
	return cfg
}

// Normalize applies the username normalization (lowercase unless replaced or disabled).
func (cfg UsernameConfig) Normalize(username string) string {
	if cfg.DisableUsernameNormalization {
		return username
	}
	if cfg.UsernameNormalization != nil {
		return cfg.UsernameNormalization(username)
	}
	return strings.ToLower(username)
}

// NormalizeDisplay applies the display username normalization (none by default).
func (cfg UsernameConfig) NormalizeDisplay(displayUsername string) string {
	if cfg.DisplayUsernameNormalization != nil {
		return cfg.DisplayUsernameNormalization(displayUsername)
	}
	return displayUsername
}

// DefaultUsernameValidator is better-auth's /^[a-zA-Z0-9_.]+$/.
func DefaultUsernameValidator(username string) bool {
	if username == "" {
		return false
	}
	for _, r := range username {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}
