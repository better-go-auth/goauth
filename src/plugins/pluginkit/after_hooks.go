package pluginkit

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	"github.com/danielgtaylor/huma/v2"
)

// AfterHook runs right before a goauth response is sent (better-auth's `hooks.after`). It can inspect the
// Set-Cookie entries the endpoint wrote (e.g. to detect a new session) and add cookies or headers.
type AfterHook func(hc *AfterHookContext)

// AfterHookContext describes the response an AfterHook runs on. It is a plugin-friendly view of
// plugins.ResponseEvent with helpers that need the Kit (signed session cookie, session lookup).
type AfterHookContext struct {
	// Path is the operation path relative to the base path (e.g. "/sign-out").
	Path string
	// Status is the HTTP status about to be written.
	Status int

	kit *Kit
	ev  *plugins.ResponseEvent

	newSessionOnce sync.Once
	newSession     *dtos.SessionWithUser
}

// Context returns the request context.
func (hc *AfterHookContext) Context() context.Context { return hc.ev.Context }

// RequestCookieHeader returns the Cookie header of the request.
func (hc *AfterHookContext) RequestCookieHeader() string { return hc.ev.RequestCookies }

// RequestCookies returns the request cookies in header order (invalid pairs are skipped).
func (hc *AfterHookContext) RequestCookies() []*http.Cookie {
	return ParseCookieHeader(hc.ev.RequestCookies)
}

// ResponseCookies returns the Set-Cookie entries written so far.
func (hc *AfterHookContext) ResponseCookies() []*http.Cookie {
	out := make([]*http.Cookie, 0, len(hc.ev.SetCookies))
	for _, raw := range hc.ev.SetCookies {
		if c, err := http.ParseSetCookie(raw); err == nil {
			out = append(out, c)
		}
	}
	return out
}

// HasResponseCookie reports whether the response sets (or expires) cookie name.
func (hc *AfterHookContext) HasResponseCookie(name string) bool {
	for _, c := range hc.ResponseCookies() {
		if c.Name == name {
			return true
		}
	}
	return false
}

// NewSessionToken returns the session token the response sets in the session_token cookie, like
// better-auth's ctx.context.newSession (every setSessionCookie call: sign-in, sign-up, refresh, ...).
func (hc *AfterHookContext) NewSessionToken() (string, bool) {
	name := hc.kit.Cookies.Name(cookies.CookieSessionToken)
	var token string
	for _, c := range hc.ResponseCookies() {
		if c.Name != name {
			continue
		}
		// a later entry for the same cookie wins (e.g. a cookie set and then expired)
		token = ""
		if c.MaxAge < 0 || c.Value == "" {
			continue
		}
		if v, ok := hc.kit.Cookies.Verify(cookies.DecodeCookieValue(c.Value)); ok {
			token = v
		}
	}
	return token, token != ""
}

// NewSession loads the session NewSessionToken refers to (nil when the response creates none).
func (hc *AfterHookContext) NewSession() *dtos.SessionWithUser {
	hc.newSessionOnce.Do(func() {
		tok, ok := hc.NewSessionToken()
		if !ok {
			return
		}
		sw, err := hc.kit.Sessions.Get(hc.ev.Context, tok)
		if err == nil {
			hc.newSession = sw
		}
	})
	return hc.newSession
}

// SetCookie adds a Set-Cookie entry to the response.
func (hc *AfterHookContext) SetCookie(c http.Cookie) {
	hc.ev.AddSetCookie(c.String())
}

// SetHeader sets a response header.
func (hc *AfterHookContext) SetHeader(name, value string) { hc.ev.SetHeader(name, value) }

// ResponseHeader returns a response header written through goauth so far.
func (hc *AfterHookContext) ResponseHeader(name string) string { return hc.ev.Headers.Get(name) }

// UseAfterHook registers fn as an OnResponse hook (plugins.HookRegistry.OnResponse) for the goauth routes
// whose path (relative to BasePath) matches match (nil matches every path). The hooks run in goauth's one
// response-hook middleware, which wraps every core and plugin route, so the plugin's init order no longer
// matters. The api argument is kept for compatibility and is not used.
func (k *Kit) UseAfterHook(_ huma.API, match func(path string) bool, fn AfterHook) {
	if fn == nil || k.Hooks == nil {
		return
	}
	k.Hooks.OnResponse(func(ev *plugins.ResponseEvent) {
		// Step 1: only the matching routes get the hook
		if match != nil && !match(ev.Path) {
			return
		}
		// Step 2: give the hook the plugin view of the response
		fn(&AfterHookContext{Path: ev.Path, Status: ev.Status, kit: k, ev: ev})
	})
}

// ParseCookieHeader parses a Cookie request header leniently (pairs that do not parse are skipped).
func ParseCookieHeader(header string) []*http.Cookie {
	var out []*http.Cookie
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			continue
		}
		out = append(out, &http.Cookie{Name: name, Value: strings.TrimSpace(value)})
	}
	return out
}
