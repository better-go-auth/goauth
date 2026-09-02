package config

import "time"

type Cookie struct {
	// ── Cookies ──────────────────────────────────────────────────────────────
	// CookiePrefix is the name prefix for auth cookies
	// (default: "better-auth" → "better-auth.session_token", …).
	CookiePrefix string
	// CookieName overrides the derived session-token cookie name (legacy hook).
	CookieName string
	// UseSecureCookies forces the Secure flag and __Secure- prefix; when false,
	// an https BaseURL still implies it (mirrors better-auth).
	UseSecureCookies bool
	// CookieDomain restricts the cookie to a specific domain.
	CookieDomain string
	// CookieSecure sets the Secure flag on the cookie (use true in production).
	CookieSecure bool
	// CookieSameSite controls the SameSite cookie attribute ("lax", "strict", "none").
	CookieSameSite string
	// CookieMaxAge overrides the cookie max-age. Zero means use SessionExpiresIn.
	// Deprecated: Max-Age now follows better-auth (Session.ExpiresIn seconds).
	CookieMaxAge time.Duration
}
