// Package config holds the options of the magic-link plugin (better-auth's MagicLinkOptions).
package config

import (
	"net/http"
	"time"
)

// SendMagicLinkData is passed to SendMagicLink (better-auth's sendMagicLink first argument).
type SendMagicLinkData struct {
	// Email is the address the link must be sent to, as supplied by the client.
	Email string `json:"email"`
	// URL is the full verification link: <origin><basePath>/magic-link/verify?token=...&callbackURL=...
	URL string `json:"url"`
	// Token is the plain verification token (the stored identifier may be its hash).
	Token string `json:"token"`
	// Metadata is the optional free-form object the client sent with the request.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// SendMagicLink delivers the magic link (e.g. by email). Returning an error fails the sign-in request.
type SendMagicLink func(data SendMagicLinkData, req *http.Request) error

// GenerateToken returns a custom verification token for email (better-auth's generateToken).
type GenerateToken func(email string) string

// StoreTokenMode selects how the token is stored in the verification table (better-auth's storeToken).
type StoreTokenMode string

const (
	// StoreTokenPlain stores the token itself as the verification identifier (default).
	StoreTokenPlain StoreTokenMode = "plain"
	// StoreTokenHashed stores base64url(SHA-256(token)) without padding.
	StoreTokenHashed StoreTokenMode = "hashed"
	// StoreTokenCustom stores Hash(token) (better-auth's { type: "custom-hasher", hash }).
	StoreTokenCustom StoreTokenMode = "custom-hasher"
)

// StoreTokenConfig mirrors better-auth's storeToken option.
type StoreTokenConfig struct {
	// Mode is "plain" (default), "hashed" or "custom-hasher". A non-nil Hash implies "custom-hasher".
	Mode StoreTokenMode
	// Hash is the custom hasher used with StoreTokenCustom.
	Hash func(token string) (string, error)
}

// RateLimitConfig mirrors better-auth's magic-link rateLimit option. It applies to /sign-in/magic-link and
// /magic-link/verify when AuthConfig.RateLimit.Enabled is set.
type RateLimitConfig struct {
	// Window is the rate limit window (default 60s).
	Window time.Duration
	// Max is the number of requests allowed per window and client IP (default 5).
	Max int
}

// MagicLinkConfig holds the options of the magic-link plugin.
type MagicLinkConfig struct {
	// SendMagicLink sends the link to the user (required).
	SendMagicLink SendMagicLink
	// ExpiresIn is how long a link stays valid (default 5 minutes).
	ExpiresIn time.Duration
	// DisableSignUp stops verify from creating users that do not exist yet.
	DisableSignUp bool
	// GenerateToken overrides the default 32-letter random token.
	GenerateToken GenerateToken
	// StoreToken selects how tokens are stored (default plain).
	StoreToken StoreTokenConfig
	// RateLimit configures the per-path rate limit rule (default 5 requests per 60s).
	RateLimit RateLimitConfig
}

// DefaultConfig returns better-auth's defaults.
func DefaultConfig() MagicLinkConfig {
	return MagicLinkConfig{
		ExpiresIn:  5 * time.Minute,
		StoreToken: StoreTokenConfig{Mode: StoreTokenPlain},
		RateLimit:  RateLimitConfig{Window: 60 * time.Second, Max: 5},
	}
}
