package goauth

import (
	"errors"
	"time"
)

// SetDefaults sets sensible default values for unspecified options.
func (opts *GoAuthOptions) SetDefaults() {
	if opts.BasePath == "" {
		opts.BasePath = "/api/auth"
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
	if opts.EmailVerification.ExpiresIn <= 0 {
		opts.EmailVerification.ExpiresIn = 15 * time.Minute
	}
}

// Validate verifies that required options are present and valid.
func (opts *GoAuthOptions) Validate() error {
	if opts.Conn == nil {
		return errors.New("goauth: database connection (Conn) is required")
	}
	if opts.SessionConfig.AccessSecret == "" {
		return errors.New("goauth: SessionConfig.AccessSecret is required")
	}
	return nil
}
