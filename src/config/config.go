package config

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/better-go-auth/goauth/src/common/consts"
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
	Secret         string
	TrustedOrigins []string
	// DisabledPaths lists endpoint paths (relative to BasePath) that are not mounted.
	DisabledPaths []string
	// DisabledOps lists operation IDs that are disabled (skipped during core route registration
	// and blocked with 404 Not Found on plugin routes).
	DisabledOps []consts.OperationId
	Advanced      Advanced

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

	GoAuth GoAuthConfig
}

// VerificationOptions mirrors better-auth's `verification` options.
type VerificationOptions struct {
	DisableCleanup bool
}

// RateLimitOptions mirrors better-auth's `rateLimit` options.
type RateLimitOptions struct {
	Enabled bool
	Window  time.Duration
	Max     int
	Storage string
}

// GoAuthConfig holds top-level options better-auth doesn't have.
type GoAuthConfig struct {
	// TablePrefix is prepended to every table name (default "": better-auth's names user, session, ...).
	TablePrefix string
	// TableNames overrides tables per better-auth model name, like better-auth's modelName (e.g. {"user": "users"}).
	TableNames map[string]string
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
