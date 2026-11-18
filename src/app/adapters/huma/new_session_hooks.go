package humaadapter

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"

	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	"github.com/danielgtaylor/huma/v2"
)

// NewSessionHooks is the old name of ResponseHooks.
//
// Deprecated: use ResponseHooks.
func NewSessionHooks(conf config.AuthConfig, hooks plugins.HookRegistry, cm *cookies.Manager) func(huma.Context, func(huma.Context)) {
	return ResponseHooks(conf, hooks, cm)
}

// ResponseHooks is goauth's single after-hook middleware. SetupGoAuth registers it once, before any plugin
// or core route is mounted, so it wraps every goauth route. Right before a response's status is written it
//
//  1. runs the OnNewSession hooks (plugins.NewSessionEvent) when the successful response sets the cookie of
//     a session created on this request (better-auth's ctx.context.newSession); a failing hook replaces the
//     response with its error, without handing out the new session cookie;
//  2. runs the OnResponse hooks (plugins.ResponseEvent, better-auth's hooks.after), which can read the
//     response cookies/headers and add their own (pluginkit.UseAfterHook registers here).
//
// Set-Cookie headers are held back until the status is written so step 1 can still drop them.
func ResponseHooks(conf config.AuthConfig, hooks plugins.HookRegistry, cm *cookies.Manager) func(huma.Context, func(huma.Context)) {
	basePath := strings.TrimSuffix(conf.BasePath, "/")
	if conf.BasePath == "" {
		basePath = "/api/auth"
	}
	return func(ctx huma.Context, next func(huma.Context)) {
		// Step 1: nothing to do unless a plugin listens, and only for goauth routes (under BasePath)
		if hooks == nil || cm == nil || (!hooks.HasNewSessionHooks() && !hooks.HasResponseHooks()) || !strings.HasPrefix(ctx.URL().Path, basePath+"/") {
			next(ctx)
			return
		}
		// Step 2: let the session manager record the sessions this request creates
		recCtx, rec := sessionsvc.WithNewSessionRecorder(ctx.Context())
		w := &newSessionWriter{
			wrappedContext: huma.WithContext(ctx, recCtx),
			hooks:          hooks,
			cookies:        cm,
			rec:            rec,
			basePath:       basePath,
			headers:        http.Header{},
		}
		// Step 3: run the endpoint; hooks fire when it writes its status
		next(w)
		// Step 4: endpoints that never wrote a status still get their cookies
		w.finish(http.StatusOK)
	}
}

// wrappedContext is huma.Context under a field name that does not hide its Context method.
type wrappedContext = huma.Context

// newSessionWriter wraps huma.Context: it buffers Set-Cookie headers and fires the new-session hooks
// right before the status is written.
type newSessionWriter struct {
	wrappedContext
	hooks    plugins.HookRegistry
	cookies  *cookies.Manager
	rec      *sessionsvc.NewSessionRecorder
	basePath string

	once      sync.Once
	setCookie []string
	headers   http.Header // non-cookie headers written so far (for ResponseEvent.Headers)
	failed    bool
}

// Unwrap returns the wrapped context (router adapters' Unwrap helpers walk this chain).
func (w *newSessionWriter) Unwrap() huma.Context { return w.wrappedContext }

func (w *newSessionWriter) SetHeader(name, value string) {
	if w.failed {
		return
	}
	if strings.EqualFold(name, "Set-Cookie") {
		w.setCookie = []string{value}
		return
	}
	w.headers.Set(name, value)
	w.wrappedContext.SetHeader(name, value)
}

func (w *newSessionWriter) AppendHeader(name, value string) {
	if w.failed {
		return
	}
	if strings.EqualFold(name, "Set-Cookie") {
		w.setCookie = append(w.setCookie, value)
		return
	}
	w.headers.Add(name, value)
	w.wrappedContext.AppendHeader(name, value)
}

func (w *newSessionWriter) SetStatus(code int) {
	w.finish(code)
	if w.failed {
		return
	}
	w.wrappedContext.SetStatus(code)
}

func (w *newSessionWriter) BodyWriter() io.Writer {
	w.finish(http.StatusOK)
	if w.failed {
		return io.Discard
	}
	return w.wrappedContext.BodyWriter()
}

// finish runs once, before the first status/body write.
func (w *newSessionWriter) finish(status int) {
	w.once.Do(func() {
		// Step 1: only successful responses that hand out a session created on this request
		if status < http.StatusBadRequest && w.hooks.HasNewSessionHooks() {
			if sw := w.newSession(); sw != nil {
				// Step 2: run the hooks with the (possibly bearer-rewritten) request
				req := httpRequestOf(w.wrappedContext)
				hookCtx := config.WithHTTPRequest(w.wrappedContext.Context(), req)
				path := strings.TrimPrefix(w.wrappedContext.URL().Path, w.basePath)
				err := w.hooks.TriggerNewSession(hookCtx, plugins.NewSessionEvent{Path: path, Session: sw, Request: req})
				if err != nil {
					// Step 3: a failing hook replaces the response; the new session cookie is not sent
					w.writeError(err)
					return
				}
			}
		}
		// Step 4: the response hooks see the final cookies/headers and may add their own
		if w.hooks.HasResponseHooks() {
			ev := plugins.NewResponseEvent(w.wrappedContext.Context(), w.operationPath(), status,
				w.wrappedContext.Header("Cookie"), w.setCookie, w.headers, w.wrappedContext.SetHeader)
			w.hooks.TriggerResponse(ev)
			w.setCookie = ev.SetCookies
		}
		// Step 5: forward the buffered cookies
		for _, c := range w.setCookie {
			w.wrappedContext.AppendHeader("Set-Cookie", c)
		}
	})
}

// newSession returns the recorded session whose token the response's session_token cookie carries.
func (w *newSessionWriter) newSession() *dtos.SessionWithUser {
	name := w.cookies.Name(cookies.CookieSessionToken)
	for _, raw := range w.setCookie {
		c, err := http.ParseSetCookie(raw)
		if err != nil || c.Name != name || c.Value == "" || c.MaxAge < 0 {
			continue
		}
		tok, ok := w.cookies.SessionToken(c.Name + "=" + c.Value)
		if !ok {
			continue
		}
		if sw := w.rec.Find(tok); sw != nil {
			return sw
		}
	}
	return nil
}

// writeError writes err in goauth's {code, message} format and drops everything the endpoint writes after.
func (w *newSessionWriter) writeError(err error) {
	w.failed = true
	ae := autherr.AsAuthError(err)
	if ae == nil || ae.StatusCode >= http.StatusInternalServerError {
		// unexpected errors are logged with a request ID; the client only gets a generic message
		ae = autherr.Internal(w.wrappedContext.Context(), err)
		w.wrappedContext.SetHeader(autherr.RequestIDHeader, ae.RequestID)
	}
	status := ae.StatusCode
	if status == 0 {
		status = http.StatusInternalServerError
	}
	w.wrappedContext.SetHeader("Content-Type", "application/json")
	w.wrappedContext.SetStatus(status)
	_ = json.NewEncoder(w.wrappedContext.BodyWriter()).Encode(ae)
}

// httpRequestOf builds an *http.Request from the current huma.Context headers (like RequestContext).
func httpRequestOf(ctx huma.Context) *http.Request {
	u := ctx.URL()
	req := &http.Request{Method: ctx.Method(), URL: &u, Host: ctx.Host(), RemoteAddr: ctx.RemoteAddr(), Header: http.Header{}}
	ctx.EachHeader(func(name, value string) { req.Header.Add(name, value) })
	return req.WithContext(ctx.Context())
}

// operationPath returns the operation's path template relative to BasePath (the URL path when the
// operation is unknown), e.g. "/sign-out".
func (w *newSessionWriter) operationPath() string {
	if op := w.wrappedContext.Operation(); op != nil && op.Path != "" {
		return strings.TrimPrefix(op.Path, w.basePath)
	}
	return strings.TrimPrefix(w.wrappedContext.URL().Path, w.basePath)
}
