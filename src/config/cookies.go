package config

import "net/http"

// CookieAttributes are better-call's CookieOptions for advanced.defaultCookieAttributes and
// advanced.cookies[name].attributes. Unset fields keep the auth cookie defaults (path "/", HttpOnly,
// SameSite=Lax, Secure from the base URL, Domain from crossSubDomainCookies).
type CookieAttributes struct {
	// Domain sets the Domain attribute.
	Domain string
	// Path sets the Path attribute.
	Path string
	// Secure overrides the Secure flag (the "__Secure-" name prefix still follows UseSecureCookies / BaseURL).
	Secure *bool
	// HTTPOnly overrides the HttpOnly flag.
	HTTPOnly *bool
	// SameSite is "lax", "strict" or "none" (case-insensitive).
	SameSite string
	// Partitioned sets the Partitioned (CHIPS) attribute.
	Partitioned *bool
}

// CookieOverride is one entry of better-auth's advanced.cookies: a custom name and/or attributes for a single
// auth cookie.
type CookieOverride struct {
	// Name replaces "<cookiePrefix>.<cookie>" (the "__Secure-" prefix is still added for secure cookies).
	Name string
	// Attributes win over DefaultCookieAttributes and the built-in defaults.
	Attributes CookieAttributes
}

// SameSiteMode returns the http.SameSite value of SameSite (0 when unset or unknown).
func (a CookieAttributes) SameSiteMode() http.SameSite {
	switch a.SameSite {
	case "lax", "Lax", "LAX":
		return http.SameSiteLaxMode
	case "strict", "Strict", "STRICT":
		return http.SameSiteStrictMode
	case "none", "None", "NONE":
		return http.SameSiteNoneMode
	}
	return 0
}

// Apply copies the set attributes onto c.
func (a CookieAttributes) Apply(c *http.Cookie) {
	if a.Domain != "" {
		c.Domain = a.Domain
	}
	if a.Path != "" {
		c.Path = a.Path
	}
	if a.Secure != nil {
		c.Secure = *a.Secure
	}
	if a.HTTPOnly != nil {
		c.HttpOnly = *a.HTTPOnly
	}
	if ss := a.SameSiteMode(); ss != 0 {
		c.SameSite = ss
	}
	if a.Partitioned != nil {
		c.Partitioned = *a.Partitioned
	}
}
