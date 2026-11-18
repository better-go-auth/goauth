// Package cookies builds, signs and reads better-auth compatible auth cookies.
package cookies

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
)

// Cookie base names used by better-auth.
const (
	CookieSessionToken = "session_token"
	CookieSessionData  = "session_data"
	CookieDontRemember = "dont_remember"
	CookieAdminSession = "admin_session"
	CookieAccountData  = "account_data"
)

const securePrefix = "__Secure-"

// Manager builds and reads better-auth's auth cookies for one configuration.
type Manager struct {
	prefix        string
	secure        bool
	domain        string
	keys          authcrypto.SecretKeys
	sessionMaxAge time.Duration
	cookieCache   *config.CookieCache
	// overrides are advanced.cookies (per-cookie name and attributes), defaults advanced.defaultCookieAttributes
	overrides map[string]config.CookieOverride
	defaults  *config.CookieAttributes
	// storeAccountCookie is account.storeAccountCookie: sign-out also deletes account_data
	storeAccountCookie bool
}

// New derives cookie names and attributes from conf (call conf.SetDefaults first).
func New(conf config.AuthConfig) *Manager {
	return &Manager{
		prefix:             conf.Advanced.CookiePrefix,
		secure:             conf.SecureCookies(),
		domain:             conf.CookieDomain(),
		keys:               authcrypto.NewSecretKeys(conf),
		sessionMaxAge:      conf.Session.ExpiresIn,
		cookieCache:        conf.Session.CookieCache,
		overrides:          conf.Advanced.Cookies,
		defaults:           conf.Advanced.DefaultCookieAttributes,
		storeAccountCookie: conf.Account.StoreAccountCookie,
	}
}

// Secret returns the current auth secret, which signs new cookies (better-auth's ctx.context.secret).
func (c *Manager) Secret() string {
	return c.keys.CurrentSecret()
}

// Keys returns the secret configuration (current secret plus older versions) used to sign, verify and encrypt.
func (c *Manager) Keys() authcrypto.SecretKeys { return c.keys }

// Verify checks a "value.signature" string against the current secret and, after a secret rotation, the
// older secrets (goauth extension: better-auth only accepts the current secret), returning value on a match.
func (c *Manager) Verify(signed string) (string, bool) {
	for _, secret := range c.keys.VerifySecrets() {
		if v, ok := VerifyCookieValue(signed, secret); ok {
			return v, true
		}
	}
	return "", false
}

// Signed returns the signed and encoded cookie value for v.
func (c *Manager) Signed(v string) string {
	return c.signed(v)
}

// Name returns the full cookie name, e.g. "__Secure-better-auth.session_token". advanced.cookies[base].Name
// replaces "<prefix>.<base>"; the "__Secure-" prefix still follows the secure setting (better-auth's createCookie).
func (c *Manager) Name(base string) string {
	name := c.plainName(base)
	if c.secure {
		return securePrefix + name
	}
	return name
}

// plainName is the cookie name without the "__Secure-" prefix.
func (c *Manager) plainName(base string) string {
	if o, ok := c.overrides[base]; ok && o.Name != "" {
		return o.Name
	}
	return c.prefix + "." + base
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
	out := []http.Cookie{
		c.cookie(CookieSessionToken, "", -1),
		c.cookie(CookieSessionData, "", -1),
		c.cookie(CookieDontRemember, "", -1),
	}
	// account.storeAccountCookie: the account_data cookie goes with the session (better-auth's deleteSessionCookie)
	if c.storeAccountCookie {
		out = append(out, c.cookie(CookieAccountData, "", -1))
	}
	return out
}

// ReadSigned returns the verified value of cookie base from a Cookie request header.
func (c *Manager) ReadSigned(cookieHeader, base string) (string, bool) {
	raw, ok := c.read(cookieHeader, base)
	if !ok {
		return "", false
	}
	return c.Verify(DecodeCookieValue(raw))
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
	cookies := parseCookieHeader(cookieHeader)
	if len(cookies) == 0 {
		return "", false
	}
	plain := c.plainName(base)
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
	return EncodeCookieValue(SignCookieValue(v, c.keys.CurrentSecret()))
}

// cookie builds auth cookie base like better-auth's createCookie: the defaults (path "/", HttpOnly,
// SameSite=Lax, Secure, crossSubDomain domain), then advanced.defaultCookieAttributes, then the per-cookie
// advanced.cookies[base].attributes.
func (c *Manager) cookie(base, value string, maxAge int) http.Cookie {
	// Step 1: built-in attributes
	ck := http.Cookie{
		Name:     c.Name(base),
		Value:    value,
		Path:     "/",
		Domain:   c.domain,
		MaxAge:   maxAge,
		Secure:   c.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	// Step 2: advanced.defaultCookieAttributes
	if c.defaults != nil {
		c.defaults.Apply(&ck)
	}
	// Step 3: advanced.cookies[base].attributes win
	if o, ok := c.overrides[base]; ok {
		o.Attributes.Apply(&ck)
	}
	return ck
}

// AdminSessionCookies returns Set-Cookie entries when an admin impersonates a user:
// sets admin_session cookie with the admin token, and session cookies for the target user.
func (c *Manager) AdminSessionCookies(adminToken string, impersonatedToken string) []http.Cookie {
	out := c.SessionCookies(impersonatedToken, false)
	out = append(out, c.cookie(CookieAdminSession, c.signed(adminToken), int(c.sessionMaxAge.Seconds())))
	return out
}

// AdminSessionToken returns the verified admin session token from admin_session cookie.
func (c *Manager) AdminSessionToken(cookieHeader string) (string, bool) {
	return c.ReadSigned(cookieHeader, CookieAdminSession)
}

// ExpireAdminSessionCookie returns a Set-Cookie entry that clears the admin_session cookie.
func (c *Manager) ExpireAdminSessionCookie() http.Cookie {
	return c.cookie(CookieAdminSession, "", -1)
}

// Cookie returns a better-auth auth cookie "<prefix>.<base>" with the shared attributes
// (path, domain, Secure, HttpOnly, SameSite=Lax). maxAge 0 is a browser-session cookie, -1 deletes it.
func (c *Manager) Cookie(base, value string, maxAge int) http.Cookie {
	return c.cookie(base, value, maxAge)
}

// SignedCookie returns an auth cookie whose value is signed with the auth secret (better-auth's setSignedCookie).
func (c *Manager) SignedCookie(base, value string, maxAge int) http.Cookie {
	return c.cookie(base, c.signed(value), maxAge)
}

// ExpireCookie returns a Set-Cookie entry deleting the auth cookie base.
func (c *Manager) ExpireCookie(base string) http.Cookie {
	return c.cookie(base, "", -1)
}

// ReadCookie returns the raw (unsigned) value of auth cookie base from a Cookie request header.
func (c *Manager) ReadCookie(cookieHeader, base string) (string, bool) {
	raw, ok := c.read(cookieHeader, base)
	if !ok {
		return "", false
	}
	return DecodeCookieValue(raw), true
}

// ─── Chunked cookies (better-auth's session store) ───────────────────────────

// chunkSize is better-auth's CHUNK_SIZE: ALLOWED_COOKIE_SIZE (4096) - ESTIMATED_EMPTY_COOKIE_SIZE (200).
const chunkSize = 4096 - 200

// maxCookieValue is the largest value better-auth sets as a single cookie.
const maxCookieValue = 4093

// ChunkedCookies returns auth cookie base holding value, split into "<name>.0", "<name>.1", ... chunks when
// it is larger than one cookie may be (better-auth's createSessionStore().chunk). Chunks found in
// cookieHeader that are no longer needed are expired.
func (c *Manager) ChunkedCookies(cookieHeader, base, value string, maxAge int) []http.Cookie {
	// Step 1: a value that fits stays one cookie, stale chunks are removed
	if len(value) <= maxCookieValue {
		out := c.expireChunks(cookieHeader, base, nil)
		return append(out, c.cookie(base, value, maxAge))
	}
	// Step 2: split the value; every chunk keeps the cookie's attributes
	var out []http.Cookie
	keep := map[string]bool{}
	for i := 0; i*chunkSize < len(value); i++ {
		end := min((i+1)*chunkSize, len(value))
		ck := c.cookie(base, value[i*chunkSize:end], maxAge)
		ck.Name += "." + strconv.Itoa(i)
		keep[ck.Name] = true
		out = append(out, ck)
	}
	// Step 3: expire chunks of an older, longer value
	return append(c.expireChunks(cookieHeader, base, keep), out...)
}

// ExpireChunkedCookies deletes auth cookie base and every chunk of it present in cookieHeader.
func (c *Manager) ExpireChunkedCookies(cookieHeader, base string) []http.Cookie {
	return append(c.expireChunks(cookieHeader, base, nil), c.cookie(base, "", -1))
}

// expireChunks returns deletions for the "<name>.<n>" chunks of base in cookieHeader that are not in keep.
func (c *Manager) expireChunks(cookieHeader, base string, keep map[string]bool) []http.Cookie {
	var out []http.Cookie
	name := c.Name(base)
	for _, ck := range parseCookieHeader(cookieHeader) {
		rest, ok := strings.CutPrefix(ck.Name, name+".")
		if !ok || keep[ck.Name] {
			continue
		}
		if _, err := strconv.Atoi(rest); err != nil {
			continue
		}
		del := c.cookie(base, "", -1)
		del.Name = ck.Name
		out = append(out, del)
	}
	return out
}

// ReadChunked returns the value of auth cookie base, joining "<name>.<n>" chunks when the cookie was split
// (better-auth's getChunkedCookie).
func (c *Manager) ReadChunked(cookieHeader, base string) (string, bool) {
	// Step 1: the whole cookie
	if v, ok := c.read(cookieHeader, base); ok {
		return DecodeCookieValue(v), true
	}
	// Step 2: chunks, ordered by index
	plain := c.plainName(base)
	type chunk struct {
		index int
		value string
	}
	var chunks []chunk
	for _, ck := range parseCookieHeader(cookieHeader) {
		rest, ok := strings.CutPrefix(strings.TrimPrefix(ck.Name, securePrefix), plain+".")
		if !ok {
			continue
		}
		idx, err := strconv.Atoi(rest)
		if err != nil {
			continue
		}
		chunks = append(chunks, chunk{idx, ck.Value})
	}
	if len(chunks) == 0 {
		return "", false
	}
	sort.Slice(chunks, func(i, j int) bool { return chunks[i].index < chunks[j].index })
	var b strings.Builder
	for _, ch := range chunks {
		b.WriteString(ch.value)
	}
	return DecodeCookieValue(b.String()), true
}

// parseCookieHeader parses a Cookie request header (nil when empty or malformed).
func parseCookieHeader(cookieHeader string) []*http.Cookie {
	if cookieHeader == "" {
		return nil
	}
	cks, err := http.ParseCookie(cookieHeader)
	if err != nil {
		return nil
	}
	return cks
}
