package humaadapter

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	"github.com/danielgtaylor/huma/v2"
)

// EndpointHookSet holds the declared endpoint hooks: the user's AuthConfig.Hooks and the plugins'
// (plugins.EndpointHooksProvider, added after each plugin's Init). It is safe for concurrent use.
type EndpointHookSet struct {
	mu     sync.RWMutex
	before []endpointhooks.BeforeHook
	after  []endpointhooks.AfterHook
	// userAfter is the number of leading after hooks that are the user's (run before goauth's built-ins)
	userAfter int
}

// NewEndpointHookSet starts a set with the user's hooks (they run first, like better-auth).
func NewEndpointHookSet(user config.HooksOptions) *EndpointHookSet {
	s := &EndpointHookSet{}
	if user.Before != nil {
		s.before = append(s.before, endpointhooks.BeforeHook{Handler: user.Before})
	}
	if user.After != nil {
		s.after = append(s.after, endpointhooks.AfterHook{Handler: user.After})
		s.userAfter = 1
	}
	return s
}

// AddPlugin appends a plugin's hooks (plugin order = run order).
func (s *EndpointHookSet) AddPlugin(h endpointhooks.Hooks) {
	if s == nil || h.Empty() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range h.Before {
		if b.Handler != nil {
			s.before = append(s.before, b)
		}
	}
	for _, a := range h.After {
		if a.Handler != nil {
			s.after = append(s.after, a)
		}
	}
}

// snapshot returns the before hooks, the user's after hooks and the plugins' after hooks.
func (s *EndpointHookSet) snapshot() (before []endpointhooks.BeforeHook, userAfter, pluginAfter []endpointhooks.AfterHook) {
	if s == nil {
		return nil, nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.before, s.after[:s.userAfter], s.after[s.userAfter:]
}

// EndpointHooks is goauth's one endpoint-hook middleware (better-auth's hooks.before / hooks.after pipeline).
// SetupGoAuth registers it once, before any plugin or core route is mounted, so it wraps every goauth
// route. For each request under BasePath it runs, in this order:
//
//  1. the before hooks (the user's AuthConfig.Hooks.Before, then plugin before hooks): they can change the
//     request headers, query and JSON body, answer instead of the endpoint, or fail the request;
//  2. the endpoint, into a response recorder;
//  3. the user's after hook (AuthConfig.Hooks.After), which sees the response and the new session;
//  4. goauth's built-in after hooks: the OnAfterSignIn interceptors (two-factor challenge) on
//     plugins.SignInInterceptorPaths, the OnNewSession hooks (a failing one replaces the response without
//     handing out the new session cookie) and the OnResponse hooks (pluginkit.UseAfterHook);
//  5. the plugin after hooks;
//
// and then writes the final response. With no hook of any kind it is a pass-through.
func EndpointHooks(conf config.AuthConfig, registry plugins.HookRegistry, cm *cookies.Manager, set *EndpointHookSet) func(huma.Context, func(huma.Context)) {
	basePath := strings.TrimSuffix(conf.BasePath, "/")
	if conf.BasePath == "" {
		basePath = "/api/auth"
	}
	return func(ctx huma.Context, next func(huma.Context)) {
		// Step 1: only goauth routes, and only when something listens
		before, userAfter, pluginAfter := set.snapshot()
		declared := len(before)+len(userAfter)+len(pluginAfter) > 0
		builtin := registry != nil && cm != nil &&
			(registry.HasAfterSignInHooks() || registry.HasNewSessionHooks() || registry.HasResponseHooks())
		if (!declared && !builtin) || !underBasePath(ctx, basePath) {
			next(ctx)
			return
		}
		// Step 2: record the sessions this request creates and wrap the context (request view + recorder)
		recCtx, rec := sessionsvc.WithNewSessionRecorder(ctx.Context())
		w := newHookContext(ctx, recCtx)
		r := &hookRun{conf: conf, registry: registry, cm: cm, rec: rec, w: w, basePath: basePath}
		r.hc = endpointhooks.NewContext(recCtx, r.path(), ctx.Method(), httpRequestOf(w), r.newSession)
		if declared {
			r.hc.Body = w.readJSONBody()
		}
		// Step 3: before hooks; a response or an error ends the request here
		if len(before) > 0 {
			if res := r.runBefore(before); res != nil {
				r.write(ctx, res)
				return
			}
		}
		// Step 4: the endpoint writes into the recorder
		next(w)
		res := w.response()
		mergeHeaders(res, r.hc.ResponseHeaders)
		r.hc.Returned = res
		// Step 5: user after hook, goauth's built-in after hooks, plugin after hooks
		r.runAfter(userAfter)
		if builtin {
			r.runBuiltin()
		}
		r.runAfter(pluginAfter)
		// Step 6: send the final response
		r.write(ctx, r.hc.Returned)
	}
}

// hookRun is the state of one request going through EndpointHooks.
type hookRun struct {
	conf     config.AuthConfig
	registry plugins.HookRegistry
	cm       *cookies.Manager
	rec      *sessionsvc.NewSessionRecorder
	w        *hookContext
	hc       *endpointhooks.Context
	basePath string

	// sessionDropped is set when a built-in hook replaced the response, so its session is no longer handed out
	sessionDropped bool
}

// path returns the operation's path template relative to BasePath (the URL path when the operation is unknown).
func (r *hookRun) path() string {
	if op := r.w.Operation(); op != nil && op.Path != "" {
		return strings.TrimPrefix(op.Path, r.basePath)
	}
	return strings.TrimPrefix(r.w.URL().Path, r.basePath)
}

// newSession returns the recorded session whose token the current response's session_token cookie carries.
func (r *hookRun) newSession() *dtos.SessionWithUser {
	if r.cm == nil || r.hc.Returned == nil || r.sessionDropped {
		return nil
	}
	name := r.cm.Name(cookies.CookieSessionToken)
	for _, c := range r.hc.Returned.Cookies() {
		if c.Name != name || c.Value == "" || c.MaxAge < 0 {
			continue
		}
		tok, ok := r.cm.SessionToken(c.Name + "=" + c.Value)
		if !ok {
			continue
		}
		if sw := r.rec.Find(tok); sw != nil {
			return sw
		}
	}
	return nil
}

// runBefore runs the matching before hooks and applies their request changes. It returns the response that
// answers the request instead of the endpoint (a hook's response or error), or nil to continue.
func (r *hookRun) runBefore(hooks []endpointhooks.BeforeHook) *endpointhooks.Response {
	// Step 1: remember the request as the endpoint would have seen it
	origBody, origQuery := encodeBody(r.hc.Body), r.hc.Query.Encode()
	// Step 2: run the hooks in order; the first response or error wins
	for _, h := range hooks {
		if h.Matcher != nil && !h.Matcher(r.hc) {
			continue
		}
		res, err := h.Handler(r.hc)
		if err != nil {
			// errors raised before the endpoint are what better-auth hands to onAPIError.onError
			out := r.errorResponse(err, true)
			mergeHeaders(out, r.hc.ResponseHeaders)
			return out
		}
		if res != nil {
			out := res.Clone()
			mergeHeaders(out, r.hc.ResponseHeaders)
			return out
		}
	}
	// Step 3: hand the (possibly changed) headers, query and body to the endpoint
	r.w.headers = r.hc.Headers
	if q := r.hc.Query.Encode(); q != origQuery {
		u := r.w.inner.URL()
		u.RawQuery = q
		r.w.url = &u
	}
	if body := encodeBody(r.hc.Body); body != nil && !bytes.Equal(body, origBody) {
		r.w.setBody(body)
	}
	// Step 4: refresh the *http.Request stored in the context so handlers and callbacks see the changes
	req := httpRequestOf(r.w)
	r.w.reqCtx = config.WithHTTPRequest(r.w.reqCtx, req)
	r.hc.Request = req
	r.hc.Ctx = r.w.reqCtx
	return nil
}

// runAfter runs matching after hooks on r.hc.Returned.
func (r *hookRun) runAfter(hooks []endpointhooks.AfterHook) {
	for _, h := range hooks {
		if h.Matcher != nil && !h.Matcher(r.hc) {
			continue
		}
		res, err := h.Handler(r.hc)
		switch {
		case err != nil:
			// a failing after hook answers with its error; cookies written so far stay (better-auth)
			out := r.errorResponse(err, false)
			for _, c := range r.hc.Returned.Header.Values("Set-Cookie") {
				out.Header.Add("Set-Cookie", c)
			}
			r.hc.Returned = out
		case res != nil:
			r.hc.Returned = res
		}
		if r.hc.Returned.Header == nil {
			r.hc.Returned.Header = http.Header{}
		}
	}
}

// runBuiltin runs goauth's built-in after hooks: sign-in interceptors, new-session hooks, response hooks.
func (r *hookRun) runBuiltin() {
	res := r.hc.Returned
	ctx := r.w.reqCtx
	// Step 1: credential sign-ins handing out a new session may be replaced (two-factor challenge)
	if res.Status < http.StatusBadRequest && r.registry.HasAfterSignInHooks() && slices.Contains(plugins.SignInInterceptorPaths, r.hc.Path) {
		if sw := r.newSession(); sw != nil {
			r.signInChallenge(ctx, sw)
		}
	}
	// Step 2: new-session hooks; a failure replaces the response and drops every cookie it set
	if r.hc.Returned.Status < http.StatusBadRequest && r.registry.HasNewSessionHooks() {
		if sw := r.newSession(); sw != nil {
			ev := plugins.NewSessionEvent{Path: r.hc.Path, Session: sw, Request: r.hc.Request}
			if err := r.registry.TriggerNewSession(ctx, ev); err != nil {
				r.hc.Returned = r.errorResponse(err, false)
				r.sessionDropped = true
			}
		}
	}
	// Step 3: response hooks see the final cookies/headers and may add their own
	if r.registry.HasResponseHooks() {
		res := r.hc.Returned
		nonCookie := res.Header.Clone()
		nonCookie.Del("Set-Cookie")
		ev := plugins.NewResponseEvent(ctx, r.hc.Path, statusOrOK(res.Status), r.hc.Headers.Get("Cookie"),
			res.Header.Values("Set-Cookie"), nonCookie, func(name, value string) { res.Header.Set(name, value) })
		r.registry.TriggerResponse(ev)
		res.Header.Del("Set-Cookie")
		for _, c := range ev.SetCookies {
			res.Header.Add("Set-Cookie", c)
		}
	}
}

// signInChallenge runs the OnAfterSignIn interceptors for a sign-in that created sw and applies the
// challenge: a replacing challenge answers 200 with its body and cookies instead of the session cookies;
// extra cookies are added to the normal response; an error replaces the response.
func (r *hookRun) signInChallenge(ctx context.Context, sw *dtos.SessionWithUser) {
	res := r.hc.Returned
	// Step 1: the event mirrors what the sign-in endpoint knew (rememberMe=false sets dont_remember)
	ev := plugins.SignInEvent{Path: r.hc.Path, Session: sw, DontRemember: r.dontRemember(res), Request: r.hc.Request}
	ch, err := r.registry.TriggerAfterSignIn(ctx, ev)
	if err != nil {
		r.hc.Returned = r.errorResponse(err, false)
		r.sessionDropped = true
		return
	}
	// Step 2: a replacing challenge: its body and cookies instead of {token, user} and the session cookies
	if ch.Replaces() {
		out := endpointhooks.JSON(http.StatusOK, ch.Body)
		for _, c := range res.Header.Values("Set-Cookie") {
			if pc, perr := http.ParseSetCookie(c); perr == nil && r.isSessionCookie(pc.Name) {
				continue
			}
			out.Header.Add("Set-Cookie", c)
		}
		for i := range ch.Cookies {
			out.SetCookie(&ch.Cookies[i])
		}
		r.hc.Returned = out
		r.sessionDropped = true
		return
	}
	// Step 3: the sign-in goes through, plus any extra cookie (e.g. a rotated trust_device cookie)
	for _, c := range ch.Extra() {
		c := c
		res.SetCookie(&c)
	}
}

// isSessionCookie reports whether name is one of the session cookies a sign-in sets.
func (r *hookRun) isSessionCookie(name string) bool {
	return name == r.cm.Name(cookies.CookieSessionToken) || name == r.cm.Name(cookies.CookieSessionData) ||
		name == r.cm.Name(cookies.CookieDontRemember)
}

// dontRemember reports whether the response sets a valid dont_remember cookie (rememberMe=false).
func (r *hookRun) dontRemember(res *endpointhooks.Response) bool {
	name := r.cm.Name(cookies.CookieDontRemember)
	for _, c := range res.Cookies() {
		if c.Name == name && c.Value != "" && c.MaxAge >= 0 && r.cm.DontRemember(c.Name+"="+c.Value) {
			return true
		}
	}
	return false
}

// errorResponse turns a hook error into goauth's {code, message} response. AuthErrors keep their status;
// anything else is an internal error (logged with a request ID, or handed to onAPIError). reportAPIError
// also hands AuthErrors to onAPIError (errors raised before the endpoint).
func (r *hookRun) errorResponse(err error, reportAPIError bool) *endpointhooks.Response {
	ctx := r.w.reqCtx
	ae := autherr.AsAuthError(err)
	header := http.Header{"Content-Type": {"application/json"}}
	if ae == nil || ae.StatusCode >= http.StatusInternalServerError {
		ae = autherr.Internal(autherr.WithRequestID(ctx, r.hc.Headers.Get(autherr.RequestIDHeader)), err)
		if ae.RequestID != "" {
			header.Set(autherr.RequestIDHeader, ae.RequestID)
		}
	} else if reportAPIError {
		autherr.Report(ctx, ae)
	}
	status := ae.StatusCode
	if status == 0 {
		status = http.StatusInternalServerError
	}
	body, _ := json.Marshal(ae)
	return &endpointhooks.Response{Status: status, Header: header, Body: append(body, '\n')}
}

// write sends res on the real context: headers (Set-Cookie entries appended), status, body.
func (r *hookRun) write(ctx huma.Context, res *endpointhooks.Response) {
	for name, values := range res.Header {
		for i, v := range values {
			if i == 0 && !strings.EqualFold(name, "Set-Cookie") {
				ctx.SetHeader(name, v)
			} else {
				ctx.AppendHeader(name, v)
			}
		}
	}
	ctx.SetStatus(statusOrOK(res.Status))
	if len(res.Body) > 0 {
		_, _ = ctx.BodyWriter().Write(res.Body)
	}
}

// mergeHeaders adds before-hook response headers to res: Set-Cookie entries are appended, others replace.
func mergeHeaders(res *endpointhooks.Response, extra http.Header) {
	if res == nil || len(extra) == 0 {
		return
	}
	if res.Header == nil {
		res.Header = http.Header{}
	}
	for name, values := range extra {
		if strings.EqualFold(name, "Set-Cookie") {
			for _, v := range values {
				res.Header.Add(name, v)
			}
			continue
		}
		res.Header[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
	}
}

// statusOrOK returns status, or 200 when no status was written.
func statusOrOK(status int) int {
	if status == 0 {
		return http.StatusOK
	}
	return status
}

// encodeBody returns the canonical JSON of a body map (nil for no body).
func encodeBody(body map[string]any) []byte {
	if body == nil {
		return nil
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil
	}
	return b
}

// ─── hookContext: request view + response recorder ──────────────────────────

// hookContext wraps huma.Context for EndpointHooks: it serves the request as changed by before hooks and
// records the response instead of writing it.
type hookContext struct {
	inner  huma.Context
	reqCtx context.Context

	// request overrides (nil = the incoming request)
	headers http.Header
	url     *url.URL
	body    io.Reader

	// recorded response
	status int
	header http.Header
	buf    bytes.Buffer
}

func newHookContext(inner huma.Context, reqCtx context.Context) *hookContext {
	return &hookContext{inner: inner, reqCtx: reqCtx, header: http.Header{}}
}

// Unwrap returns the wrapped context (router adapters' Unwrap helpers walk this chain).
func (w *hookContext) Unwrap() huma.Context { return w.inner }

func (w *hookContext) Operation() *huma.Operation { return w.inner.Operation() }
func (w *hookContext) Context() context.Context   { return w.reqCtx }
func (w *hookContext) TLS() *tls.ConnectionState  { return w.inner.TLS() }
func (w *hookContext) Version() huma.ProtoVersion { return w.inner.Version() }
func (w *hookContext) Method() string             { return w.inner.Method() }
func (w *hookContext) Host() string               { return w.inner.Host() }
func (w *hookContext) RemoteAddr() string         { return w.inner.RemoteAddr() }
func (w *hookContext) Param(name string) string   { return w.inner.Param(name) }

func (w *hookContext) URL() url.URL {
	if w.url != nil {
		return *w.url
	}
	return w.inner.URL()
}

func (w *hookContext) Query(name string) string {
	if w.url != nil {
		return w.url.Query().Get(name)
	}
	return w.inner.Query(name)
}

func (w *hookContext) Header(name string) string {
	if w.headers != nil {
		return w.headers.Get(name)
	}
	return w.inner.Header(name)
}

func (w *hookContext) EachHeader(cb func(name, value string)) {
	if w.headers == nil {
		w.inner.EachHeader(cb)
		return
	}
	for name, values := range w.headers {
		for _, v := range values {
			cb(name, v)
		}
	}
}

func (w *hookContext) BodyReader() io.Reader {
	if w.body != nil {
		return w.body
	}
	return w.inner.BodyReader()
}

func (w *hookContext) GetMultipartForm() (*multipart.Form, error) { return w.inner.GetMultipartForm() }
func (w *hookContext) SetReadDeadline(t time.Time) error          { return w.inner.SetReadDeadline(t) }

func (w *hookContext) SetStatus(code int)           { w.status = code }
func (w *hookContext) Status() int                  { return w.status }
func (w *hookContext) SetHeader(name, value string) { w.header.Set(name, value) }
func (w *hookContext) AppendHeader(name, value string) {
	w.header.Add(name, value)
}
func (w *hookContext) BodyWriter() io.Writer { return &w.buf }

// response returns what the endpoint wrote.
func (w *hookContext) response() *endpointhooks.Response {
	return &endpointhooks.Response{Status: w.status, Header: w.header, Body: w.buf.Bytes()}
}

// setBody replaces the request body.
func (w *hookContext) setBody(b []byte) { w.body = bytes.NewReader(b) }

// readJSONBody buffers a JSON request body (up to the operation's MaxBodyBytes) so hooks can read it, and
// returns it decoded when it is a JSON object. The endpoint still reads the same bytes.
func (w *hookContext) readJSONBody() map[string]any {
	// Step 1: only bodies Huma decodes as JSON
	switch w.inner.Method() {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return nil
	}
	ct := strings.ToLower(w.inner.Header("Content-Type"))
	if ct != "" && !strings.Contains(ct, "json") {
		return nil
	}
	// Step 2: read at most MaxBodyBytes; the endpoint gets the bytes back (and the rest of an oversized body)
	limit := int64(1 << 20)
	if op := w.inner.Operation(); op != nil && op.MaxBodyBytes > 0 {
		limit = op.MaxBodyBytes
	}
	src := w.inner.BodyReader()
	if src == nil {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(src, limit))
	w.body = io.MultiReader(bytes.NewReader(data), src)
	if err != nil || int64(len(data)) >= limit {
		return nil
	}
	w.body = bytes.NewReader(data)
	// Step 3: decode JSON objects (numbers stay json.Number so they re-encode unchanged)
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var body map[string]any
	if dec.Decode(&body) != nil {
		return nil
	}
	return body
}
