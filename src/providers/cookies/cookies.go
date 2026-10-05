// Package cookies builds, signs and reads better-auth compatible auth cookies.
package cookies

import (
	"net/http"
	"time"

	"github.com/better-go-auth/goauth/src/config"
)

// Cookie base names used by better-auth.
const (
	CookieSessionToken = "session_token"
	CookieSessionData  = "session_data"
	CookieDontRemember = "dont_remember"
)

const securePrefix = "__Secure-"

// Manager builds and reads better-auth's auth cookies for one configuration.
type Manager struct {
	prefix        string
	secure        bool
	domain        string
	secret        string
	sessionMaxAge time.Duration
}

// New derives cookie names and attributes from conf (call conf.SetDefaults first).
func New(conf config.AuthConfig) *Manager {
	return &Manager{
		prefix:        conf.Advanced.CookiePrefix,
		secure:        conf.SecureCookies(),
		domain:        conf.CookieDomain(),
		secret:        conf.Secret,
		sessionMaxAge: conf.Session.ExpiresIn,
	}
}

// Name returns the full cookie name, e.g. "__Secure-better-auth.session_token".
func (c *Manager) Name(base string) string {
	name := c.prefix + "." + base
	if c.secure {
		return securePrefix + name
	}
	return name
}

// SessionCookies returns the Set-Cookie entries for a new or refreshed session.
// With dontRemember the token cookie lasts for the browser session and a dont_remember marker is added.
func (c *Manager) SessionCookies(token string, dontRemember bool) []http.Cookie {
	maxAge := int(c.sessionMaxAge.Seconds())
	if dontRemember {
		maxAge = 0
	}
	out := []http.Cookie{c.cookie(CookieSessionToken, c.signed(token), maxAge)}
	if dontRemember {
		out = append(out, c.cookie(CookieDontRemember, c.signed("true"), 0))
	}
	return out
}

// ExpireSessionCookies returns Set-Cookie entries that delete every session cookie.
func (c *Manager) ExpireSessionCookies() []http.Cookie {
	return []http.Cookie{
		c.cookie(CookieSessionToken, "", -1),
		c.cookie(CookieSessionData, "", -1),
		c.cookie(CookieDontRemember, "", -1),
	}
}

// ReadSigned returns the verified value of cookie base from a Cookie request header.
func (c *Manager) ReadSigned(cookieHeader, base string) (string, bool) {
	raw, ok := c.read(cookieHeader, base)
	if !ok {
		return "", false
	}
	return VerifyCookieValue(DecodeCookieValue(raw), c.secret)
}

// SessionToken returns the verified session token from a Cookie request header.
func (c *Manager) SessionToken(cookieHeader string) (string, bool) {
	return c.ReadSigned(cookieHeader, CookieSessionToken)
}

// DontRemember reports whether the request carries a valid dont_remember marker.
func (c *Manager) DontRemember(cookieHeader string) bool {
	v, ok := c.ReadSigned(cookieHeader, CookieDontRemember)
	return ok && v == "true"
}

// read prefers the configured name and falls back to the other secure variant, as better-auth does.
func (c *Manager) read(cookieHeader, base string) (string, bool) {
	if cookieHeader == "" {
		return "", false
	}
	cookies, err := http.ParseCookie(cookieHeader)
	if err != nil {
		return "", false
	}
	plain := c.prefix + "." + base
	names := []string{securePrefix + plain, plain}
	if !c.secure {
		names = []string{plain, securePrefix + plain}
	}
	for _, name := range names {
		for _, ck := range cookies {
			if ck.Name == name && ck.Value != "" {
				return ck.Value, true
			}
		}
	}
	return "", false
}

func (c *Manager) signed(v string) string {
	return EncodeCookieValue(SignCookieValue(v, c.secret))
}

func (c *Manager) cookie(base, value string, maxAge int) http.Cookie {
	return http.Cookie{
		Name:     c.Name(base),
		Value:    value,
		Path:     "/",
		Domain:   c.domain,
		MaxAge:   maxAge,
		Secure:   c.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}
