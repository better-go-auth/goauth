// Package config holds the options of the multi-session plugin (better-auth's MultiSessionConfig).
package config

// DefaultMaximumSessions is better-auth's default maximumSessions.
const DefaultMaximumSessions = 5

// MultiSessionConfig holds the options of the multi-session plugin.
type MultiSessionConfig struct {
	// MaximumSessions is the maximum number of sessions a device (browser) can hold (default 5).
	MaximumSessions int
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
