package config

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"github.com/better-go-auth/goauth/src/common/consts"
	"github.com/better-go-auth/goauth/src/common/logger"
	socialproviders "github.com/better-go-auth/goauth/src/plugins/social/providers"
	"github.com/better-go-auth/goauth/src/schema"
)

type AuthConfig struct {
	AppName string
	// BaseURL is the public origin of the auth server (e.g. https://example.com).
	/**
	 * Base URL for the Better Auth. This is typically the
	 * root URL where your application server is hosted.
	 *
	 * Can be configured as:
	 * - A static string: `"https://myapp.com"`
	 * - A dynamic config with allowed hosts for multi-domain deployments
	 *
	 * If not explicitly set, the system will check environment variables:
	 * `BETTER_AUTH_URL`, `NEXT_PUBLIC_BETTER_AUTH_URL`, etc.
	 *
	 * @example
	 * ```ts
	 * // Static URL
	 * baseURL: "https://myapp.com"
	 *
	 * // Dynamic with allowed hosts (for Vercel, multi-domain, etc.)
	 * baseURL: {
	 *   allowedHosts: ["myapp.com", "*.vercel.app", "preview-*.myapp.com"],
	 *   fallback: "https://myapp.com"
	 * }
	 * ```
	 */
	BaseURL string
	// BasePath is the base mount path for Better Auth routes (default: "/api/auth").
	/**
	 * Base path for the Better Auth. This is typically
	 * the path where the
	 * Better Auth routes are mounted.
	 *
	 * @default "/api/auth"
	 */
	BasePath string // usualy /api/auth
	// Secret signs cookies and tokens; defaults to $BETTER_AUTH_SECRET.
	Secret string
	// Secrets enables better-auth's secret rotation (`secrets`, or $BETTER_AUTH_SECRETS as
	// "<version>:<secret>,..."): the first entry signs and encrypts, older entries still decrypt and verify.
	// When set, SetDefaults replaces Secret with the first entry and keeps the old Secret only to decrypt
	// bare-hex payloads written before rotation (see secrets.go).
	Secrets []SecretVersion
	// TrustedOrigins are origins (wildcards allowed, e.g. "https://*.example.com") trusted for redirects and
	// the origin/CSRF check, besides the base URL (better-auth's trustedOrigins as an array).
	TrustedOrigins []string
	// TrustedOriginsFunc adds origins computed from each request (better-auth's trustedOrigins as a function).
	// It is also called once at startup with a nil request.
	TrustedOriginsFunc func(r *http.Request) []string
	// DynamicBaseURL resolves the base URL per request from the Host / X-Forwarded-Host header, for
	// multi-domain and preview deployments (better-auth's baseURL: {allowedHosts, fallback, protocol}).
	// When set, BaseURL may be empty; it defaults to Fallback.
	DynamicBaseURL *DynamicBaseURL
	// SocialProviders are better-auth's core `socialProviders`: setting them installs the social plugin
	// (/sign-in/social, /callback/{id}, /link-social, /get-access-token, /refresh-token, /account-info),
	// configured from these providers and Account (linking policy, token encryption, state strategy).
	SocialProviders []socialproviders.Provider
	// DisabledPaths lists endpoint paths (relative to BasePath) that are not mounted.
	DisabledPaths []string
	// DisabledOps lists operation IDs that are disabled (skipped during core route registration
	// and blocked with 404 Not Found on plugin routes).
	DisabledOps []consts.OperationId
	Advanced    Advanced

	secrets            secretState
	cachedSecure       *bool
	cachedCookieDomain string
	cachedDomainOnce   bool

	EmailAndPassword  EmailAndPassword
	EmailVerification EmailVerification
	Session           Session
	User              UserOptions
	Account           AccountOptions
	Verification      VerificationOptions
	RateLimit         RateLimitOptions
	Security          SecurityConfig
	// Hooks are better-auth's endpoint `hooks.before` / `hooks.after` (see hooks.go).
	Hooks HooksOptions
	// OnAPIError is better-auth's `onAPIError` (errorURL, onError, throw; see api_error.go).
	OnAPIError OnAPIErrorOptions
	// Logger is better-auth's `logger` option (level, disabled, custom log function).
	Logger logger.Options

	GoAuth GoAuthConfig
}

// VerificationOptions mirrors better-auth's `verification` options.
type VerificationOptions struct {
	DisableCleanup bool

	// ModelName renames the verification table (better-auth's verification.modelName).
	ModelName string
	// Fields renames verification columns: field name → column name (better-auth's verification.fields).
	Fields map[string]string
	// AdditionalFields adds verification fields (better-auth's verification.additionalFields).
	AdditionalFields map[string]schema.Field

	// StoreIdentifier is how verification identifiers (tokens, OTP keys, ...) are written to the verification
	// table: plain (default), hashed (SHA-256, unpadded base64url) or a custom hash (better-auth's
	// verification.storeIdentifier). Rows written before a change keep working: lookups fall back to the plain
	// identifier.
	StoreIdentifier StoreIdentifierOption
	// StoreIdentifierOverrides choose another option for identifiers starting with a prefix, e.g.
	// {"reset-password:": {Mode: "hashed"}} (better-auth's storeIdentifier.overrides). The longest matching
	// prefix wins.
	StoreIdentifierOverrides map[string]StoreIdentifierOption
}

// GoAuthConfig holds top-level options better-auth doesn't have.
type GoAuthConfig struct {
	// TablePrefix is prepended to every table name (default "": better-auth's names user, session, ...).
	TablePrefix string
	// TableNames overrides tables per better-auth model name, like better-auth's modelName (e.g. {"user": "users"}).
	TableNames map[string]string
	// ColumnCase picks the column naming of fields without an explicit column name: schema.Snake (default,
	// goauth's existing layout, e.g. email_verified) or schema.Camel (better-auth's default layout, e.g.
	// emailVerified, needed to share a database with a TypeScript better-auth server).
	ColumnCase schema.ColumnCase
}

// DeriveKey derives a purpose-specific key from secret (hex HMAC-SHA256), so one secret can feed several signers.
func DeriveKey(secret, purpose string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(purpose))
	return hex.EncodeToString(mac.Sum(nil))
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
