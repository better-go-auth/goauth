package config

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/better-go-auth/goauth/src/common/consts"
	"github.com/better-go-auth/goauth/src/common/logger"
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
	Secret         string
	TrustedOrigins []string
	// DisabledPaths lists endpoint paths (relative to BasePath) that are not mounted.
	DisabledPaths []string
	// DisabledOps lists operation IDs that are disabled (skipped during core route registration
	// and blocked with 404 Not Found on plugin routes).
	DisabledOps []consts.OperationId
	Advanced    Advanced

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
	// Migrations decides what SetupGoAuth does with the database schema (default MigrationsAuto).
	Migrations MigrationsOptions
}

// MigrationMode is GoAuthConfig.Migrations.Mode.
type MigrationMode string

const (
	// MigrationsAuto (default, also "") applies additive changes at startup: missing tables, columns and
	// indexes of the schema registry (core models, additionalFields, plugin schemas, rateLimit) and the
	// tables of plugins that still migrate their GORM structs. Nothing is ever dropped or altered.
	MigrationsAuto MigrationMode = "auto"
	// MigrationsVerify inspects the database at startup and fails, listing every missing table, column and
	// index with the SQL that creates it, instead of changing anything. Use it when a migration tool
	// (Atlas, goose, golang-migrate, ...) owns the schema; generate its input with goauth.GenerateSQL /
	// goauth.GenerateMigration or the goauth CLI.
	MigrationsVerify MigrationMode = "verify"
	// MigrationsOff trusts the operator: no inspection, no DDL.
	MigrationsOff MigrationMode = "off"
)

// MigrationsOptions configure schema migrations (doc 04 §6).
type MigrationsOptions struct {
	// Mode is MigrationsAuto (default), MigrationsVerify or MigrationsOff.
	Mode MigrationMode
}

// EffectiveMode returns Mode with "" resolved to MigrationsAuto, or an error for unknown modes.
func (m MigrationsOptions) EffectiveMode() (MigrationMode, error) {
	switch MigrationMode(strings.ToLower(string(m.Mode))) {
	case "", MigrationsAuto:
		return MigrationsAuto, nil
	case MigrationsVerify:
		return MigrationsVerify, nil
	case MigrationsOff:
		return MigrationsOff, nil
	}
	return "", fmt.Errorf("goauth: unknown GoAuth.Migrations.Mode %q (use auto, verify or off)", m.Mode)
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
