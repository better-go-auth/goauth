// Package config holds the options of the one-time-token plugin (better-auth's OneTimeTokenOptions).
package config

import (
	"context"
	"time"

	"github.com/better-go-auth/goauth/src/models/dtos"
)

// DefaultExpiresIn is better-auth's default token lifetime (expiresIn: 3 minutes).
const DefaultExpiresIn = 3 * time.Minute

// GenerateTokenFunc returns a custom token for session (better-auth's generateToken).
type GenerateTokenFunc func(ctx context.Context, session *dtos.SessionWithUser) (string, error)

// StoreTokenMode selects how the token is stored in the verification table (better-auth's storeToken).
type StoreTokenMode string

const (
	// StoreTokenPlain stores the token itself in the verification identifier (default).
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

// OneTimeTokenConfig holds the options of the one-time-token plugin.
type OneTimeTokenConfig struct {
	// ExpiresIn is how long a token stays valid (default 3 minutes).
	ExpiresIn time.Duration
	// DisableClientRequest rejects GET /one-time-token/generate over HTTP; tokens can then only be created
	// on the server with OneTimeTokenService.GenerateToken.
	DisableClientRequest bool
	// DisableSetSessionCookie stops /one-time-token/verify from setting the session cookie.
	DisableSetSessionCookie bool
	// GenerateToken overrides the default 32-character random token.
	GenerateToken GenerateTokenFunc
	// StoreToken selects how tokens are stored (default plain).
	StoreToken StoreTokenConfig
	// SetOttHeaderOnNewSession adds a fresh token in the `set-ott` response header to every response that
	// sets a new session cookie (exposed through Access-Control-Expose-Headers).
	SetOttHeaderOnNewSession bool
}

// DefaultConfig returns better-auth's defaults.
func DefaultConfig() OneTimeTokenConfig {
	return OneTimeTokenConfig{ExpiresIn: DefaultExpiresIn, StoreToken: StoreTokenConfig{Mode: StoreTokenPlain}}
}

// WithDefaults fills unset options with better-auth's defaults.
func (c OneTimeTokenConfig) WithDefaults() OneTimeTokenConfig {
	if c.ExpiresIn <= 0 {
		c.ExpiresIn = DefaultExpiresIn
	}
	if c.StoreToken.Mode == "" {
		c.StoreToken.Mode = StoreTokenPlain
		if c.StoreToken.Hash != nil {
			c.StoreToken.Mode = StoreTokenCustom
		}
	}
	return c
}
