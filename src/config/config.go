package config

import (
	"context"
	"net/http"

	conf "github.com/birukbelay/gocmn/src/config"
)

type EnvConfig struct {
	// Env string `koanf:"ENV"`

	ServerPort string `koanf:"SERVER_PORT"`
	ServerHost string `koanf:"SERVER_HOST"`

	SqlDbConfig conf.SqlDbConfig `koanf:",squash"`
	conf.JwtVar

	conf.KeyValConfig
	FireBasePath string `koanf:"FIREBASE_SERVICE_ACCOUNT_PATH"`

	//test related
	TestDbName        string `koanf:"TEST_DB_NAME"`
	UseTestContainers string `koanf:"USE_TEST_CONTAINERS"`
	// WebLink                     string `koanf:"WEB_LINK"`
}

type VerificationConfig struct {
	CodeLen int
}

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

// AuthConfig is the top-level configuration struct.
// Pass this when constructing BetterGoAuth via bettergoauth.New(Options{Config: ...}).
type AuthConfig struct {
	AppName string

	// ── URLs ─────────────────────────────────────────────────────────────────
	// BaseURL is the public base URL of the application, used to build callback and
	// email verification links (e.g. "https://example.com").
	BaseURL string
	/**
	 * Base path for the Better Auth. This is typically
	 * the path where the
	 * Better Auth routes are mounted.
	 *
	 * @default "/api/auth"
	 */
	BasePath string
	// ── Secrets ──────────────────────────────────────────────────────────────
	// Secret is the master secret used for HMAC signing of opaque session tokens.
	Secret string

	SecondaryStorage  conf.KeyValConfig
	EmailVerification *EmailVerification
	EmailAndPassword  *EmailAndPassword
	Session           *Session

	conf.JwtVar

	// AccessSecret signs JWT access tokens (only relevant in JWT mode).
	// Deprecated: configure this via dedicated token/plugin options
	// AccessSecret string
	// RefreshSecret signs JWT refresh tokens (only relevant in JWT mode).
	// Deprecated: configure this via dedicated token/plugin options
	// RefreshSecret string

	// ── RBAC ────────────────────────────────────────────────────────────────
	// DefaultRole is assigned to new users on sign-up (default: "user").
	DefaultRole string

	// TrustedOrigins lists origins allowed to send cross-origin requests.
	TrustedOrigins []string
}

// type SecondaryStorage interface {
// 	Get(key string) (any, error)
// 	GetAndDelete(key string) (any, error)
// 	Set(key string, value string, ttl time.Duration) error
// 	Delete(key string) error
// }

func (c AuthConfig) WithDefaults() AuthConfig {
	return c
}
