// Package config holds the options of the one-tap plugin (better-auth's OneTapOptions).
package config

import (
	"net/http"
	"time"
)

// GoogleJWKSURL is Google's key set; better-auth verifies One Tap ID tokens against it.
const GoogleJWKSURL = "https://www.googleapis.com/oauth2/v3/certs"

// GoogleIssuers are the issuers better-auth accepts in a One Tap ID token.
var GoogleIssuers = []string{"https://accounts.google.com", "accounts.google.com"}

// OneTapConfig holds the options of the one-tap plugin.
type OneTapConfig struct {
	// ClientID is the Google OAuth client ID the ID token must be issued for ("aud"). When empty, the
	// client ID of the social plugin's "google" provider is used (OneTapConfig.Social / WithSocialPlugin),
	// like better-auth's `options.clientId || socialProviders.google.clientId`. With neither, the audience
	// is not checked (better-auth's jwtVerify with audience undefined).
	ClientID string
	// DisableSignup refuses to create a user for an unknown Google account (better-auth's disableSignup):
	// the callback answers 401 "signup disabled".
	DisableSignup bool

	// JWKSURL overrides Google's key set URL (GoogleJWKSURL); tests point it at a fake JWKS.
	JWKSURL string
	// HTTPClient fetches the JWKS (default: a client with a 10 second timeout).
	HTTPClient *http.Client
}

// WithDefaults fills the unset options.
func (c OneTapConfig) WithDefaults() OneTapConfig {
	if c.JWKSURL == "" {
		c.JWKSURL = GoogleJWKSURL
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return c
}
