package config

import (
	"errors"
	"fmt"
	"github.com/better-go-auth/goauth/src/common/logger"
	"net/url"
	"os"
	"sync"
	"time"
)

// SetDefaults sets sensible default values for unspecified options.
func (opts *AuthConfig) SetDefaults() {
	// 1. Resolve BaseURL from environment variables if not explicitly provided (Better Auth standard)
	if opts.BaseURL == "" {
		opts.BaseURL = os.Getenv(BaseURLEnvVar)
		if opts.BaseURL == "" {
			opts.BaseURL = os.Getenv(NextBaseURLEnvVar)
		}
	}
	// with a dynamic base URL the static BaseURL (used outside requests) is the fallback origin
	if opts.BaseURL == "" && opts.DynamicBaseURL != nil {
		opts.BaseURL = originOf(opts.DynamicBaseURL.Fallback)
	}
	// 2. Set default application name and routes mount path
	if opts.AppName == "" {
		opts.AppName = DefaultAppName
	}
	if opts.BasePath == "" {
		opts.BasePath = "/api/auth"
	}
	// 3. Resolve Secret like better-auth: options.secret || $BETTER_AUTH_SECRET || $AUTH_SECRET ||
	// DEFAULT_SECRET. The development default is refused in production by Validate; with
	// Advanced.GoAuth.RequireSecret a missing secret is an error everywhere (goauth's old behaviour).
	// With versioned Secrets (or $BETTER_AUTH_SECRETS) the first entry becomes Secret and the old single
	// secret is kept as the legacy secret for bare-hex payloads (better-auth's secret rotation).
	opts.resolveSecrets()
	if opts.Secret == "" {
		opts.Secret = os.Getenv(SecretEnvVar)
	}
	if opts.Secret == "" {
		opts.Secret = os.Getenv(AuthSecretEnvVar)
	}
	if opts.Secret == "" && !opts.Advanced.GoAuth.RequireSecret {
		opts.Secret = DefaultDevSecret
	}
	// 4. Set session updatable fields default
	if opts.Session.GoAuth.UpdatableFields == nil {
		opts.Session.GoAuth.UpdatableFields = DefaultUpdatableSessionFields
	}
	// 5. Set advanced cookie prefix and IPv6 subnet defaults
	if opts.Advanced.CookiePrefix == "" {
		opts.Advanced.CookiePrefix = DefaultCookiePrefix
	}
	if opts.Advanced.IPAddress.IPv6Subnet <= 0 {
		opts.Advanced.IPAddress.IPv6Subnet = DefaultIPv6Subnet
	}

	// 6. Set email and password length constraints and reset token lifetime defaults
	if opts.EmailAndPassword.MinPasswordLength <= 0 {
		opts.EmailAndPassword.MinPasswordLength = 8
	}
	if opts.EmailAndPassword.MaxPasswordLength <= 0 {
		opts.EmailAndPassword.MaxPasswordLength = 128
	}
	if opts.EmailAndPassword.ResetPasswordTokenExpiresIn <= 0 {
		opts.EmailAndPassword.ResetPasswordTokenExpiresIn = time.Hour
	}
	// 7. Cache SecureCookies/CookieDomain to avoid url.Parse per request
	{
		sc := opts.SecureCookiesCached()
		opts.cachedSecure = &sc
		opts.cachedCookieDomain = opts.CookieDomainCached()
		opts.cachedDomainOnce = true
	}

	// 8. Set session storage and lifetime defaults
	if !opts.Session.StoreSessionInDatabaseSet && !opts.Session.StoreSessionInDatabase {
		opts.Session.StoreSessionInDatabase = true
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
	// 9. Set email verification and user deletion token lifetime defaults
	if opts.EmailVerification.ExpiresIn <= 0 {
		opts.EmailVerification.ExpiresIn = time.Hour
	}
	if opts.User.DeleteUser.DeleteTokenExpiresIn <= 0 {
		opts.User.DeleteUser.DeleteTokenExpiresIn = 24 * time.Hour
	}
	if opts.EmailVerification.GoAuth.CodeExpiresIn <= 0 {
		opts.EmailVerification.GoAuth.CodeExpiresIn = 15 * time.Minute
	}
	// 10. Set CookieCache defaults if enabled (Better Auth standards: 5m, compact, version 1)
	if opts.Session.CookieCache != nil && opts.Session.CookieCache.IsEnabled() {
		if opts.Session.CookieCache.MaxAge <= 0 {
			opts.Session.CookieCache.MaxAge = 5 * time.Minute
		}
		if opts.Session.CookieCache.Strategy == "" {
			opts.Session.CookieCache.Strategy = CookieCacheStrategyCompact
		}
		if opts.Session.CookieCache.Version == "" {
			opts.Session.CookieCache.Version = "1"
		}
		if opts.Session.CookieCache.RefreshCache != nil && opts.Session.CookieCache.RefreshCache.UpdateAge <= 0 {
			opts.Session.CookieCache.RefreshCache.UpdateAge = opts.Session.CookieCache.MaxAge / 5
		}
	}
}

// devSecretWarning logs the development-secret warning once per process instead of once per setup.
var devSecretWarning sync.Once

// Validate verifies that required options are present and valid.
func (opts *AuthConfig) Validate() error {
	// 1. Validate BaseURL (required in Better Auth; checked here or from environment), or the dynamic base URL
	if d := opts.DynamicBaseURL; d != nil {
		if len(d.AllowedHosts) == 0 {
			return errors.New(`goauth: DynamicBaseURL.AllowedHosts cannot be empty; provide at least one allowed host pattern (e.g. "myapp.com", "*.vercel.app")`)
		}
		switch d.Protocol {
		case "", "auto", "http", "https":
		default:
			return fmt.Errorf("goauth: DynamicBaseURL.Protocol %q must be http, https or auto", d.Protocol)
		}
		if d.Fallback != "" && originOf(d.Fallback) == "" {
			return fmt.Errorf("goauth: DynamicBaseURL.Fallback %q must be an absolute URL", d.Fallback)
		}
	} else if opts.BaseURL == "" {
		return fmt.Errorf("goauth: BaseURL (or $%s) is required", BaseURLEnvVar)
	}
	if opts.BaseURL != "" {
		u, err := url.Parse(opts.BaseURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("goauth: BaseURL %q must be an absolute URL", opts.BaseURL)
		}
	}

	// 2. Validate CrossSubDomainCookies requirements
	if opts.Advanced.CrossSubDomainCookies.Enabled && opts.CookieDomain() == "" {
		return errors.New("goauth: CrossSubDomainCookies requires Domain or BaseURL")
	}

	// 3. Validate Secret presence and recommended length (versioned Secrets first, like better-auth's
	// validateSecretsArray)
	if opts.secrets.envErr != nil {
		return fmt.Errorf("goauth: %w", opts.secrets.envErr)
	}
	if len(opts.Secrets) > 0 {
		warnings, err := validateSecrets(opts.Secrets)
		if err != nil {
			return err
		}
		for _, w := range warnings {
			logger.Warn(w)
		}
	}
	if opts.Secret == "" {
		return fmt.Errorf("goauth: Secret (or $%s / $%s) is required", SecretEnvVar, AuthSecretEnvVar)
	}
	// a public development secret would let anyone forge cookies and tokens, so production refuses it
	if IsDevSecret(opts.Secret) {
		if IsProduction() {
			return errors.New("goauth: you are using the default secret; set a random BETTER_AUTH_SECRET in production")
		}
		devSecretWarning.Do(func() {
			logger.Warn("goauth: Secret is a public development default; never use it in production")
		})
	}
	if len(opts.Secret) < MinSecretLength {
		logger.Warn("goauth: Secret is shorter than recommended", "min", MinSecretLength, "len", len(opts.Secret))
	}

	// 4. Validate the ID format, the migrations mode and the schema options
	if _, err := opts.Advanced.Database.IDGenerator(); err != nil {
		return fmt.Errorf("goauth: Advanced.Database.IDFormat: %w", err)
	}
	if _, err := opts.GoAuth.Migrations.EffectiveMode(); err != nil {
		return err
	}

	// 5. Validate CookieCache if enabled
	if opts.Session.CookieCache != nil && opts.Session.CookieCache.IsEnabled() {
		switch opts.Session.CookieCache.Strategy {
		case CookieCacheStrategyCompact, CookieCacheStrategyJwt, CookieCacheStrategyJwe, "":
		default:
			return fmt.Errorf("goauth: invalid cookieCache strategy %q (must be compact, jwt, or jwe)", opts.Session.CookieCache.Strategy)
		}
		if opts.Session.CookieCache.MaxAge < 0 {
			return errors.New("goauth: cookieCache maxAge cannot be negative")
		}
	}
	return nil
}
