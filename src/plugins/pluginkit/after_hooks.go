package pluginkit

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	"github.com/danielgtaylor/huma/v2"
)

// AfterHook runs right before a goauth response is sent (better-auth's `hooks.after`). It can inspect the
// Set-Cookie entries the endpoint wrote (e.g. to detect a new session) and add cookies or headers.
type AfterHook func(hc *AfterHookContext)

// AfterHookContext describes the response an AfterHook runs on.
type AfterHookContext struct {
	// Path is the operation path relative to the base path (e.g. "/sign-out").
	Path string
	// Status is the HTTP status about to be written.
	Status int

	kit        *Kit
	ctx        context.Context
	reqCookies string
	setCookies []string
	headers    http.Header
	inner      huma.Context

	newSessionOnce sync.Once
	newSession     *dtos.SessionWithUser
}

// Context returns the request context.
func (hc *AfterHookContext) Context() context.Context { return hc.ctx }

// RequestCookieHeader returns the Cookie header of the request.
func (hc *AfterHookContext) RequestCookieHeader() string { return hc.reqCookies }

// RequestCookies returns the request cookies in header order (invalid pairs are skipped).
func (hc *AfterHookContext) RequestCookies() []*http.Cookie { return ParseCookieHeader(hc.reqCookies) }

// ResponseCookies returns the Set-Cookie entries written so far.
func (hc *AfterHookContext) ResponseCookies() []*http.Cookie {
	out := make([]*http.Cookie, 0, len(hc.setCookies))
	for _, raw := range hc.setCookies {
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
		if v, ok := cookies.VerifyCookieValue(cookies.DecodeCookieValue(c.Value), hc.kit.Cookies.Secret()); ok {
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
		sw, err := hc.kit.Sessions.Get(hc.ctx, tok)
		if err == nil {
			hc.newSession = sw
		}
	})
	return hc.newSession
}

// SetCookie adds a Set-Cookie entry to the response.
func (hc *AfterHookContext) SetCookie(c http.Cookie) {
	v := c.String()
	if v == "" {
		return
	}
	hc.setCookies = append(hc.setCookies, v)
	hc.inner.AppendHeader("Set-Cookie", v)
}

// SetHeader sets a response header.
func (hc *AfterHookContext) SetHeader(name, value string) {
	hc.headers.Set(name, value)
	hc.inner.SetHeader(name, value)
}

// ResponseHeader returns a response header written through goauth so far.
func (hc *AfterHookContext) ResponseHeader(name string) string { return hc.headers.Get(name) }

// UseAfterHook registers fn as a Huma API middleware that runs on every goauth route (paths under BasePath)
// mounted after the call, matching match (nil matches every path). Core routes are mounted after all plugins,
// so they are always covered; routes of plugins initialized earlier are not.
func (k *Kit) UseAfterHook(api huma.API, match func(path string) bool, fn AfterHook) {
	if api == nil || fn == nil {
		return
	}
	api.UseMiddleware(func(ctx huma.Context, next func(huma.Context)) {
		// Step 1: only goauth routes get the hook
		op := ctx.Operation()
		if op == nil || !strings.HasPrefix(op.Path, k.BasePath+"/") {
			next(ctx)
			return
		}
		path := strings.TrimPrefix(op.Path, k.BasePath)
		if match != nil && !match(path) {
			next(ctx)
			return
		}
		// Step 2: wrap the context so the hook sees the response headers before they are sent
		w := &afterHookWriter{innerContext: ctx, fn: fn, hc: &AfterHookContext{
			Path:       path,
			kit:        k,
			ctx:        ctx.Context(),
			reqCookies: ctx.Header("Cookie"),
			headers:    http.Header{},
			inner:      ctx,
		}}
		next(w)
		// Step 3: endpoints that wrote nothing still get the hook (net/http sends 200 afterwards)
		w.run(http.StatusOK)
	})
}

// innerContext is huma.Context under a field name that does not hide its Context method.
type innerContext = huma.Context

// afterHookWriter records the headers an endpoint writes and runs the hook once, right before the status
// line (and with it the headers) is sent.
type afterHookWriter struct {
	innerContext
	fn   AfterHook
	hc   *AfterHookContext
	done bool
}

// Unwrap returns the wrapped context (used by humago.Unwrap).
func (w *afterHookWriter) Unwrap() huma.Context { return w.innerContext }

func (w *afterHookWriter) SetHeader(name, value string) {
	w.record(name, value, false)
	w.innerContext.SetHeader(name, value)
}

func (w *afterHookWriter) AppendHeader(name, value string) {
	w.record(name, value, true)
	w.innerContext.AppendHeader(name, value)
}

func (w *afterHookWriter) SetStatus(code int) {
	w.run(code)
	w.innerContext.SetStatus(code)
}

func (w *afterHookWriter) BodyWriter() io.Writer {
	w.run(http.StatusOK)
	return w.innerContext.BodyWriter()
}

func (w *afterHookWriter) record(name, value string, appendValue bool) {
	if strings.EqualFold(name, "Set-Cookie") {
		if !appendValue {
			w.hc.setCookies = w.hc.setCookies[:0]
		}
		w.hc.setCookies = append(w.hc.setCookies, value)
		return
	}
	if appendValue {
		w.hc.headers.Add(name, value)
	} else {
		w.hc.headers.Set(name, value)
	}
}

func (w *afterHookWriter) run(status int) {
	if w.done {
		return
	}
	w.done = true
	w.hc.Status = status
	w.fn(w.hc)
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
