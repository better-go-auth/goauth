package config

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"
)

type AuthConfig struct {
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
	Session           Session
	User              UserOptions
	Account           AccountOptions

	GoAuth GoAuthConfig
}

// GoAuthConfig holds top-level options better-auth doesn't have.
type GoAuthConfig struct {
	// Mode selects the exposed API surface (default ModeLegacy).
	Mode Mode
	// Session holds goauth-only session options (single session, legacy JWTs).
	Session SessionGoAuth
	// TablePrefix is prepended to every table name (default "": better-auth's names user, session, ...).
	TablePrefix string
	// TableNames overrides tables per better-auth model name, like better-auth's modelName (e.g. {"user": "users"}).
	TableNames map[string]string
}

// SetDefaults sets sensible default values for unspecified options.
func (opts *AuthConfig) SetDefaults() {
	if opts.GoAuth.Mode == "" {
		opts.GoAuth.Mode = ModeLegacy
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
	jwt := &opts.GoAuth.Session.JWT
	if opts.Secret == "" && opts.GoAuth.Mode == ModeLegacy {
		opts.Secret = jwt.AccessSecret
	}
	if jwt.AccessSecret == "" && opts.Secret != "" {
		jwt.AccessSecret = DeriveKey(opts.Secret, "goauth-access")
	}
	if jwt.RefreshSecret == "" && opts.Secret != "" {
		jwt.RefreshSecret = DeriveKey(opts.Secret, "goauth-refresh")
	}
	if jwt.AccessExpiresIn <= 0 {
		jwt.AccessExpiresIn = time.Hour
	}
	if jwt.RefreshExpiresIn <= 0 {
		jwt.RefreshExpiresIn = 7 * 24 * time.Hour
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
	if opts.EmailVerification.ExpiresIn <= 0 {
		opts.EmailVerification.ExpiresIn = time.Hour
	}
	if opts.EmailVerification.GoAuth.CodeExpiresIn <= 0 {
		opts.EmailVerification.GoAuth.CodeExpiresIn = 15 * time.Minute
	}
}

// DeriveKey derives a purpose-specific key from secret (hex HMAC-SHA256), so one secret can feed several signers.
func DeriveKey(secret, purpose string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(purpose))
	return hex.EncodeToString(mac.Sum(nil))
}

// Validate verifies that required options are present and valid.
func (opts *AuthConfig) Validate() error {
	switch opts.GoAuth.Mode {
	case "", ModeLegacy:
	case ModeCompat:
		if opts.Secret == "" {
			return fmt.Errorf("goauth: Secret (or $%s) is required in compat mode", SecretEnvVar)
		}
		if opts.BaseURL == "" {
			return errors.New("goauth: BaseURL is required in compat mode")
		}
	default:
		return fmt.Errorf("goauth: unknown Mode %q", opts.GoAuth.Mode)
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
	jwt := opts.GoAuth.Session.JWT
	if jwt.AccessSecret == "" || jwt.RefreshSecret == "" {
		return errors.New("goauth: Secret (or GoAuth.Session.JWT.AccessSecret and RefreshSecret) is required")
	}
	if jwt.AccessSecret == jwt.RefreshSecret {
		return errors.New("goauth: GoAuth.Session.JWT.AccessSecret and RefreshSecret must differ")
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
