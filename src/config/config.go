package config

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"
)

type AuthConfig struct {
	// Mode selects the exposed API surface (default ModeLegacy).
	Mode    Mode
	AppName string
	// BasePath is the base mount path for Better Auth routes (default: "/api/auth").
	BasePath string // usualy /api/auth
	// BaseURL is the public origin of the auth server (e.g. https://example.com).
	BaseURL string
	// Secret signs cookies and tokens; defaults to $BETTER_AUTH_SECRET.
	Secret         string
	TrustedOrigins []string
	// DisabledPaths lists endpoint paths (relative to BasePath) that are not mounted.
	DisabledPaths []string
	Advanced      Advanced

	EmailAndPassword  EmailAndPassword
	EmailVerification EmailVerification
	// SessionConfig configures the legacy JWT access/refresh flow.
	SessionConfig SessionConfig
	// Session configures better-auth style cookie sessions (compat mode).
	Session Session
}

// SetDefaults sets sensible default values for unspecified options.
func (opts *AuthConfig) SetDefaults() {
	if opts.Mode == "" {
		opts.Mode = ModeLegacy
	}
	if opts.AppName == "" {
		opts.AppName = DefaultAppName
	}
	if opts.BasePath == "" {
		opts.BasePath = "/api/auth"
	}
	if opts.Secret == "" {
		opts.Secret = os.Getenv(SecretEnvVar)
	}
	if opts.Secret == "" && opts.Mode == ModeLegacy {
		opts.Secret = opts.SessionConfig.AccessSecret
	}
	// legacy routes are still mounted in compat mode and need a JWT secret
	if opts.SessionConfig.AccessSecret == "" && opts.Mode == ModeCompat {
		opts.SessionConfig.AccessSecret = opts.Secret
	}
	if opts.Advanced.CookiePrefix == "" {
		opts.Advanced.CookiePrefix = DefaultCookiePrefix
	}
	if opts.Advanced.IPAddress.IPv6Subnet <= 0 {
		opts.Advanced.IPAddress.IPv6Subnet = DefaultIPv6Subnet
	}
	if opts.EmailAndPassword.MinPasswordLength <= 0 {
		opts.EmailAndPassword.MinPasswordLength = 8
	}
	if opts.EmailAndPassword.MaxPasswordLength <= 0 {
		opts.EmailAndPassword.MaxPasswordLength = 128
	}
	if opts.EmailAndPassword.ResetPasswordTokenExpiresIn <= 0 {
		opts.EmailAndPassword.ResetPasswordTokenExpiresIn = time.Hour
	}
	if opts.Session.ExpiresIn <= 0 {
		opts.Session.ExpiresIn = 7 * 24 * time.Hour
	}
	if opts.Session.UpdateAge <= 0 {
		opts.Session.UpdateAge = 24 * time.Hour
	}
	if opts.Session.FreshAge == 0 {
		opts.Session.FreshAge = 24 * time.Hour
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
	switch opts.Mode {
	case "", ModeLegacy:
		if opts.SessionConfig.AccessSecret == "" {
			return errors.New("goauth: SessionConfig.AccessSecret is required")
		}
	case ModeCompat:
		if opts.Secret == "" {
			return fmt.Errorf("goauth: Secret (or $%s) is required in compat mode", SecretEnvVar)
		}
		if opts.BaseURL == "" {
			return errors.New("goauth: BaseURL is required in compat mode")
		}
	default:
		return fmt.Errorf("goauth: unknown Mode %q", opts.Mode)
	}
	if opts.BaseURL != "" {
		u, err := url.Parse(opts.BaseURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("goauth: BaseURL %q must be an absolute URL", opts.BaseURL)
		}
	}
	if opts.Advanced.CrossSubDomainCookies.Enabled && opts.CookieDomain() == "" {
		return errors.New("goauth: CrossSubDomainCookies requires Domain or BaseURL")
	}
	if opts.SessionConfig.AccessSecret == "" {
		return errors.New("goauth: SessionConfig.AccessSecret is required")
	}
	if opts.Secret != "" && len(opts.Secret) < MinSecretLength {
		slog.Warn("goauth: Secret is shorter than recommended", "min", MinSecretLength, "len", len(opts.Secret))
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
