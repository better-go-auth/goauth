// Package config holds the options of the have-i-been-pwned plugin (better-auth's HaveIBeenPwnedOptions).
package config

import (
	"net/http"
	"time"
)

// DefaultAPIURL is the Pwned Passwords range API; the 5-character SHA-1 prefix is appended.
const DefaultAPIURL = "https://api.pwnedpasswords.com/range/"

// DefaultPaths are the endpoints whose new passwords are checked (better-auth's default paths).
var DefaultPaths = []string{"/sign-up/email", "/change-password", "/reset-password"}

// DefaultHTTPTimeout bounds one range API call.
const DefaultHTTPTimeout = 30 * time.Second

// HaveIBeenPwnedConfig holds the options of the have-i-been-pwned plugin.
type HaveIBeenPwnedConfig struct {
	// CustomPasswordCompromisedMessage replaces the PASSWORD_COMPROMISED message.
	CustomPasswordCompromisedMessage string
	// Paths are the endpoints (relative to BasePath) whose new passwords are checked (default DefaultPaths).
	// Any endpoint that hashes a new password can be listed, e.g. "/email-otp/reset-password",
	// "/phone-number/reset-password", "/set-password" or "/admin/set-user-password".
	Paths []string
	// Enabled turns the check off when set to false (default true).
	Enabled *bool
	// APIURL is the range API base URL, the SHA-1 prefix is appended (default DefaultAPIURL; tests point it
	// at a fake server).
	APIURL string
	// HTTPClient performs the range API calls (default: a client with DefaultHTTPTimeout).
	HTTPClient *http.Client
}

// WithDefaults fills unset options with better-auth's defaults.
func (c HaveIBeenPwnedConfig) WithDefaults() HaveIBeenPwnedConfig {
	if len(c.Paths) == 0 {
		c.Paths = append([]string(nil), DefaultPaths...)
	}
	if c.APIURL == "" {
		c.APIURL = DefaultAPIURL
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: DefaultHTTPTimeout}
	}
	return c
}

// IsEnabled reports whether passwords are checked (Enabled unset or true).
func (c HaveIBeenPwnedConfig) IsEnabled() bool { return c.Enabled == nil || *c.Enabled }
