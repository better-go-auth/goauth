// Package services implements better-auth's multi-session plugin: one signed cookie per session a device
// signed in with, so a browser can hold several accounts and switch between them.
package services

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins/multi-session/config"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
	"github.com/better-go-auth/goauth/src/providers/cookies"
)

// Error codes (better-auth's MULTI_SESSION_ERROR_CODES).
var (
	ErrInvalidSessionToken = pluginkit.NewError(http.StatusUnauthorized, "INVALID_SESSION_TOKEN", "Invalid session token")
)

// ErrorCodes maps better-auth's MULTI_SESSION_ERROR_CODES keys to their messages.
var ErrorCodes = map[string]string{
	"INVALID_SESSION_TOKEN": "Invalid session token",
}

// multiMarker is what better-auth's isMultiSessionCookie looks for in a cookie name.
const multiMarker = "_multi-"

// IsMultiSessionCookie reports whether name is a multi-session cookie (better-auth's isMultiSessionCookie).
func IsMultiSessionCookie(name string) bool { return strings.Contains(name, multiMarker) }

// DeviceCookie is a verified multi-session cookie of the request.
type DeviceCookie struct {
	// Name is the cookie name as sent by the browser.
	Name string
	// Token is the session token the cookie holds.
	Token string
}

// MultiSessionService holds the multi-session logic.
type MultiSessionService struct {
	cfg config.MultiSessionConfig
	kit *pluginkit.Kit
}

// NewMultiSessionService builds the service.
func NewMultiSessionService(cfg config.MultiSessionConfig, kit *pluginkit.Kit) *MultiSessionService {
	return &MultiSessionService{cfg: cfg.WithDefaults(), kit: kit}
}

// Config returns the effective configuration.
func (s *MultiSessionService) Config() config.MultiSessionConfig { return s.cfg }

// Kit returns the shared plugin runtime.
func (s *MultiSessionService) Kit() *pluginkit.Kit { return s.kit }

// cookieBase is the auth-cookie base name of token's multi-session cookie ("session_token_multi-<token>").
func cookieBase(token string) string {
	return cookies.CookieSessionToken + multiMarker + strings.ToLower(token)
}

// CookieName returns the full multi-session cookie name of token:
// `<session_token cookie name>_multi-<token lowercased>`.
func (s *MultiSessionService) CookieName(token string) string {
	return s.kit.Cookies.Name(cookieBase(token))
}

// multiCookie is the signed multi-session cookie for token, with the session_token cookie's attributes.
func (s *MultiSessionService) multiCookie(token string) http.Cookie {
	return s.kit.Cookies.SignedCookie(cookieBase(token), token, int(s.kit.Conf.Session.ExpiresIn.Seconds()))
}

// expireNamed returns a Set-Cookie entry deleting cookie name, with the session_token cookie's attributes.
func (s *MultiSessionService) expireNamed(name string) http.Cookie {
	c := s.kit.Cookies.ExpireCookie(cookies.CookieSessionToken)
	c.Name = name
	return c
}

// verify returns the value of a signed cookie value (as sent by the browser).
func (s *MultiSessionService) verify(raw string) (string, bool) {
	return s.kit.Cookies.Verify(cookies.DecodeCookieValue(raw))
}

// DeviceCookies returns the multi-session cookies of cookieHeader whose signature is valid, in header order.
func (s *MultiSessionService) DeviceCookies(cookieHeader string) []DeviceCookie {
	var out []DeviceCookie
	for _, c := range pluginkit.ParseCookieHeader(cookieHeader) {
		if !IsMultiSessionCookie(c.Name) {
			continue
		}
		if tok, ok := s.verify(c.Value); ok && tok != "" {
			out = append(out, DeviceCookie{Name: c.Name, Token: tok})
		}
	}
	return out
}

// hasDeviceCookie reports whether cookieHeader holds a valid multi-session cookie for token
// (better-auth's ctx.getSignedCookie(multiSessionCookieName)).
func (s *MultiSessionService) hasDeviceCookie(cookieHeader, token string) bool {
	if token == "" {
		return false
	}
	v, ok := s.kit.Cookies.ReadSigned(cookieHeader, cookieBase(token))
	if !ok {
		return false
	}
	// config: GoAuth.StrictDeviceCookie also requires the cookie to hold the requested token, not just share
	// its lowercased name (better-auth only checks that the signed cookie exists)
	if s.cfg.GoAuth.StrictDeviceCookie {
		return authcrypto.SecureEqual(v, token)
	}
	return true
}

// live returns the session for token when it exists and has not expired.
func (s *MultiSessionService) live(ctx context.Context, token string) *dtos.SessionWithUser {
	sw, err := s.kit.Sessions.Get(ctx, token)
	if err != nil || sw == nil || !time.Time(sw.Session.ExpiresAt).After(time.Now()) {
		return nil
	}
	return sw
}

// ListDeviceSessions returns the live sessions of the device's multi-session cookies, one per user
// (GET /multi-session/list-device-sessions).
func (s *MultiSessionService) ListDeviceSessions(ctx context.Context, cookieHeader string) []dtos.SessionWithUser {
	out := []dtos.SessionWithUser{}
	// Step 1: collect the verified tokens of the multi-session cookies
	devices := s.DeviceCookies(cookieHeader)
	if len(devices) == 0 {
		return out
	}
	// Step 2: keep live sessions, the first one of each user
	seen := map[string]bool{}
	for _, d := range devices {
		sw := s.live(ctx, d.Token)
		if sw == nil || seen[sw.User.ID] {
			continue
		}
		seen[sw.User.ID] = true
		out = append(out, *sw)
	}
	return out
}

// SetActive makes token the device's active session (POST /multi-session/set-active).
// It returns the session and the cookies to set; on an unknown session the returned cookies expire its
// multi-session cookie and the error is INVALID_SESSION_TOKEN.
func (s *MultiSessionService) SetActive(ctx context.Context, cookieHeader, token string) (*dtos.SessionWithUser, []http.Cookie, error) {
	// Step 1: the device must hold a multi-session cookie for the token
	if !s.hasDeviceCookie(cookieHeader, token) {
		return nil, nil, ErrInvalidSessionToken
	}
	// Step 2: a dead session drops its multi-session cookie
	sw := s.live(ctx, token)
	if sw == nil {
		return nil, []http.Cookie{s.expireNamed(s.CookieName(token))}, ErrInvalidSessionToken
	}
	// Step 3: swap the session cookie (keeping the dont_remember choice of the device)
	return sw, s.kit.SessionCookies(sw, s.kit.Cookies.DontRemember(cookieHeader)), nil
}

// Revoke deletes the device session token (POST /multi-session/revoke). When it is the current session,
// the next live device session becomes active, or the session cookies are cleared when there is none.
func (s *MultiSessionService) Revoke(ctx context.Context, cookieHeader string, current *dtos.SessionWithUser, token string) ([]http.Cookie, error) {
	// Step 1: the device must hold a multi-session cookie for the token
	if !s.hasDeviceCookie(cookieHeader, token) {
		return nil, ErrInvalidSessionToken
	}
	// Step 2: delete the session and its multi-session cookie
	_ = s.kit.Sessions.Delete(ctx, token)
	out := []http.Cookie{s.expireNamed(s.CookieName(token))}
	// Step 3: revoking another session leaves the active one alone
	if current == nil || current.Session.Token != token {
		return out, nil
	}
	// Step 4: switch to the first remaining live device session, or sign the device out
	for _, d := range s.DeviceCookies(cookieHeader) {
		if sw := s.live(ctx, d.Token); sw != nil {
			return append(out, s.kit.SessionCookies(sw, s.kit.Cookies.DontRemember(cookieHeader))...), nil
		}
	}
	return append(out, s.kit.ExpireSessionCookies(false)...), nil
}

// AfterHook is better-auth's multi-session after hooks: it adds a multi-session cookie to every response
// that sets a new session cookie, and revokes every device session on /sign-out.
func (s *MultiSessionService) AfterHook(hc *pluginkit.AfterHookContext) {
	s.onNewSession(hc)
	if hc.Path == "/sign-out" {
		s.onSignOut(hc)
	}
}

// onNewSession stores the response's new session in a multi-session cookie, replacing the device's other
// sessions of the same user and respecting MaximumSessions.
func (s *MultiSessionService) onNewSession(hc *pluginkit.AfterHookContext) {
	ctx := hc.Context()
	// Step 1: only responses that set a session cookie for an existing session
	newSession := hc.NewSession()
	if newSession == nil {
		return
	}
	token := newSession.Session.Token
	name := s.CookieName(token)
	// Step 2: nothing to do when the device already holds (or is getting) the cookie
	if hc.HasResponseCookie(name) {
		return
	}
	reqCookies := hc.RequestCookies()
	for _, c := range reqCookies {
		if c.Name == name {
			return
		}
	}
	// Step 3: drop the device's other sessions of the same user
	var multiKeys []string
	deleted := 0
	for _, c := range reqCookies {
		if !IsMultiSessionCookie(c.Name) {
			continue
		}
		multiKeys = append(multiKeys, c.Name)
		tok, ok := s.verify(c.Value)
		if !ok || tok == "" {
			continue
		}
		sw, err := s.kit.Sessions.Get(ctx, tok)
		if err != nil || sw == nil || sw.User.ID != newSession.User.ID {
			continue
		}
		_ = s.kit.Sessions.Delete(ctx, tok)
		hc.SetCookie(s.expireNamed(c.Name))
		deleted++
	}
	// Step 4: respect the per-device maximum (the new session counts as one)
	if len(multiKeys)-deleted+1 > s.cfg.MaximumSessions {
		return
	}
	// Step 5: remember the new session on the device
	hc.SetCookie(s.multiCookie(token))
}

// onSignOut revokes every session of the device's multi-session cookies and expires those cookies.
func (s *MultiSessionService) onSignOut(hc *pluginkit.AfterHookContext) {
	ctx := hc.Context()
	for _, c := range hc.RequestCookies() {
		if !IsMultiSessionCookie(c.Name) {
			continue
		}
		tok, ok := s.verify(c.Value)
		if !ok || tok == "" {
			continue
		}
		// Step 1: expire the cookie (better-auth lowercases the name, keeping the __Secure- prefix)
		hc.SetCookie(s.expireNamed(normalizeCookieName(c.Name)))
		// Step 2: revoke the session
		_ = s.kit.Sessions.Delete(ctx, tok)
	}
}

// normalizeCookieName is better-auth's key.toLowerCase().replace("__secure-", "__Secure-").
func normalizeCookieName(name string) string {
	return strings.Replace(strings.ToLower(name), strings.ToLower(securePrefix), securePrefix, 1)
}

const securePrefix = "__Secure-"
