package config

import (
	"context"
	"errors"
	"net/http"
	"time"
)

type AuthConfig struct {
	// BasePath is the base mount path for Better Auth routes (default: "/api/auth").
	BasePath          string // usualy /api/auth
	BaseURL           string //// this is the domain of the frontend app
	EmailVerification EmailVerification
	SessionConfig     SessionConfig
}

// SetDefaults sets sensible default values for unspecified options.
func (opts *AuthConfig) SetDefaults() {
	if opts.BasePath == "" {
		opts.BasePath = "/api/auth"
	}
	if opts.SessionConfig.RevocationPrefix == "" {
		opts.SessionConfig.RevocationPrefix = "revoked:session"
	}
	if opts.SessionConfig.BlacklistPrefix == "" {
		opts.SessionConfig.BlacklistPrefix = "blacklisted"
	}
	if opts.SessionConfig.AccessExpireMin <= 0 {
		opts.SessionConfig.AccessExpireMin = 60 // 1 hour
	}
	if opts.SessionConfig.RefreshExpireMin <= 0 {
		opts.SessionConfig.RefreshExpireMin = 10080 // 7 days (7 * 24 * 60 min)
	}
	if opts.SessionConfig.RefreshSecret == "" && opts.SessionConfig.AccessSecret != "" {
		opts.SessionConfig.RefreshSecret = opts.SessionConfig.AccessSecret
	}
	// verification sender
	if opts.EmailVerification.ExpiresIn <= 0 {
		opts.EmailVerification.ExpiresIn = 15 * time.Minute
	}
}

// Validate verifies that required options are present and valid.
func (opts *AuthConfig) Validate() error {
	if opts.SessionConfig.AccessSecret == "" {
		return errors.New("goauth: SessionConfig.AccessSecret is required")
	}
	return nil
}

//======================  other defaults ==============

type contextKey string

const httpRequestKey contextKey = "http_request"

// WithHTTPRequest stores the *http.Request in the context.
func WithHTTPRequest(ctx context.Context, req *http.Request) context.Context {
	return context.WithValue(ctx, httpRequestKey, req)
}

// GetHTTPRequest retrieves the *http.Request from the context.
func GetHTTPRequest(ctx context.Context) *http.Request {
	if req, ok := ctx.Value(httpRequestKey).(*http.Request); ok {
		return req
	}
	return nil
}

// type SecondaryStorage interface {
// 	Get(key string) (any, error)
// 	GetAndDelete(key string) (any, error)
// 	Set(key string, value string, ttl time.Duration) error
// 	Delete(key string) error
// }

// func (c AuthConfigs) WithDefaults() AuthConfigs {
// 	return c
// }
