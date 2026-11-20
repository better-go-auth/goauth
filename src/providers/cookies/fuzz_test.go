package cookies

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/better-go-auth/goauth/src/config"
)

// fuzzManager is a cookie manager with the cookie cache on, so ReadSessionData decodes cached sessions.
func fuzzManager() *Manager {
	cfg := config.AuthConfig{BaseURL: "http://localhost:3000", Secret: "fuzz-secret-0123456789abcdef0123456789"}
	enabled := true
	cfg.Session.CookieCache = &config.CookieCache{Enabled: &enabled, MaxAge: time.Minute, Strategy: config.CookieCacheStrategyCompact}
	return New(cfg)
}

// FuzzReadSigned feeds arbitrary Cookie headers to every reader of signed cookies: nothing may panic, and a
// value accepted as signed must verify again when it is signed by the manager (no partial or forged reads).
func FuzzReadSigned(f *testing.F) {
	m := fuzzManager()
	name := m.Name(CookieSessionToken)
	// Step 1: seeds: valid signed cookies (plain and URL-encoded), forged signatures, odd separators
	f.Add(name + "=" + m.Signed("session-token-123"))
	f.Add(name + "=" + SignCookieValue("tok", "fuzz-secret-0123456789abcdef0123456789"))
	f.Add("a=b; " + name + "=" + m.Signed("x.y.z") + "; c=d")
	f.Add(name + "=tok.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	f.Add(name + "=%zz%; " + name + "=")
	f.Add(";;; =; " + name)
	f.Add(m.Name(CookieSessionData) + "=" + strings.Repeat("A", 64))
	f.Add("__Secure-" + name + "=" + m.Signed("secure"))
	f.Fuzz(func(t *testing.T, header string) {
		// Step 2: readers never panic
		v, ok := m.ReadSigned(header, CookieSessionToken)
		tok, tokOK := m.SessionToken(header)
		_, _ = m.AdminSessionToken(header)
		_ = m.DontRemember(header)
		_, _ = m.ReadSessionData(header)
		// Step 3: the session token reader is ReadSigned on the session cookie
		if ok != tokOK || v != tok {
			t.Fatalf("SessionToken disagrees with ReadSigned: %q/%v vs %q/%v", tok, tokOK, v, ok)
		}
		// Step 4: an accepted value is exactly what the manager signs
		if ok {
			if got, ok := m.Verify(DecodeCookieValue(m.Signed(v))); !ok || got != v {
				t.Fatalf("accepted value %q does not round-trip (%q, %v)", v, got, ok)
			}
		}
	})
}

// FuzzSignedRoundTrip: every value the manager signs is read back unchanged from a Cookie header, and a
// signature made with another secret is refused.
func FuzzSignedRoundTrip(f *testing.F) {
	m := fuzzManager()
	for _, seed := range []string{"token", "a.b.c", "with space", "ünïcödé", "=+/%", strings.Repeat("x", 300)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		// Step 1: cookie values are UTF-8 strings without control characters; the header separators ';' and
		// ',' are escaped by the encoding
		if value == "" || !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n") {
			t.Skip()
		}
		// Step 2: round trip through a Cookie header
		header := "other=1; " + m.Name(CookieSessionToken) + "=" + m.Signed(value)
		got, ok := m.ReadSigned(header, CookieSessionToken)
		if !ok || got != value {
			t.Fatalf("round trip of %q: got %q, %v", value, got, ok)
		}
		// Step 3: another secret's signature is refused
		forged := m.Name(CookieSessionToken) + "=" + EncodeCookieValue(SignCookieValue(value, "another-secret-0123456789abcdef012345"))
		if _, ok := m.ReadSigned(forged, CookieSessionToken); ok {
			t.Fatalf("a cookie signed with another secret was accepted for %q", value)
		}
	})
}

// FuzzVerifyCookieValue: the low-level verifier never panics and only accepts "value.signature" strings
// whose signature is the HMAC of value.
func FuzzVerifyCookieValue(f *testing.F) {
	const secret = "fuzz-secret-0123456789abcdef0123456789"
	f.Add(SignCookieValue("v", secret))
	f.Add(".")
	f.Add("a.")
	f.Add(".=")
	f.Add("v." + strings.Repeat("=", 44))
	f.Fuzz(func(t *testing.T, signed string) {
		v, ok := VerifyCookieValue(signed, secret)
		_ = DecodeCookieValue(signed)
		if ok && SignCookieValue(v, secret) != signed {
			t.Fatalf("accepted %q, which is not the signature of %q", signed, v)
		}
	})
}
