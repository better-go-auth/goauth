package config

// AuthConfigs is the top-level configuration struct.
// Pass this when constructing BetterGoAuth via bettergoauth.New(Options{Config: ...}).
// type AuthConfigs struct {
// 	AppName string

// 	// ── URLs ─────────────────────────────────────────────────────────────────
// 	// BaseURL is the public base URL of the application, used to build callback and
// 	// email verification links (e.g. "https://example.com").
// 	BaseURL string
// 	/**
// 	 * Base path for the Better Auth. This is typically
// 	 * the path where the
// 	 * Better Auth routes are mounted.
// 	 *
// 	 * @default "/api/auth"
// 	 */
// 	BasePath string
// 	// ── Secrets ──────────────────────────────────────────────────────────────
// 	// Secret is the master secret used for HMAC signing of opaque session tokens.
// 	Secret string

// 	SecondaryStorage  SecondaryStorage
// 	EmailVerification *EmailVerification
// 	EmailAndPassword  *EmailAndPassword
// 	Session           *Session

// 	// conf.JwtVar

// 	// AccessSecret signs JWT access tokens (only relevant in JWT mode).
// 	// Deprecated: configure this via dedicated token/plugin options
// 	// AccessSecret string
// 	// RefreshSecret signs JWT refresh tokens (only relevant in JWT mode).
// 	// Deprecated: configure this via dedicated token/plugin options
// 	// RefreshSecret string

// 	// ── RBAC ────────────────────────────────────────────────────────────────
// 	// DefaultRole is assigned to new users on sign-up (default: "user").
// 	DefaultRole string

// 	// TrustedOrigins lists origins allowed to send cross-origin requests.
// 	TrustedOrigins []string
// }
