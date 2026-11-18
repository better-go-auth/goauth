// Package config holds the options of the multi-session plugin (better-auth's MultiSessionConfig).
package config

// DefaultMaximumSessions is better-auth's default maximumSessions.
const DefaultMaximumSessions = 5

// MultiSessionConfig holds the options of the multi-session plugin.
type MultiSessionConfig struct {
	// MaximumSessions is the maximum number of sessions a device (browser) can hold (default 5).
	MaximumSessions int

	// GoAuth holds multi-session options better-auth doesn't have.
	GoAuth MultiSessionGoAuth
}

// MultiSessionGoAuth holds multi-session options better-auth doesn't have.
type MultiSessionGoAuth struct {
	// StrictDeviceCookie makes set-active / revoke require that the signed device cookie holds exactly the
	// requested session token. better-auth (the default) only requires a validly signed cookie under the
	// token's lowercased name, so two tokens differing only in letter case share a cookie.
	StrictDeviceCookie bool
}

// DefaultConfig returns better-auth's defaults.
func DefaultConfig() MultiSessionConfig {
	return MultiSessionConfig{MaximumSessions: DefaultMaximumSessions}
}

// WithDefaults fills unset options with better-auth's defaults.
func (c MultiSessionConfig) WithDefaults() MultiSessionConfig {
	if c.MaximumSessions <= 0 {
		c.MaximumSessions = DefaultMaximumSessions
	}
	return c
}
