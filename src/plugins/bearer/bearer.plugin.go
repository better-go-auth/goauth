package bearer

import (
	"context"
	"log/slog"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"mime/multipart"
	"net/url"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	humaadapter "github.com/better-go-auth/goauth/src/app/adapters/huma"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
)

const PluginID = "bearer"

// Plugin implements plugins.Plugin for Better Auth's Bearer token authentication.
// It converts incoming Authorization: Bearer <token> headers to session cookies (before hook)
// and returns set-auth-token headers when session cookies are set (after hook).
type Plugin struct {
	config bearerconfig.BearerConfig
}

var _ plugins.Plugin = (*Plugin)(nil)

// Option configures the Bearer Plugin.
type Option func(*Plugin)

// WithRequireSignature sets whether only signed tokens are accepted.
func WithRequireSignature(req bool) Option {
	return func(p *Plugin) {
		p.config.RequireSignature = req
	}
}

// WithConfig sets the entire BearerConfig.
func WithConfig(cfg bearerconfig.BearerConfig) Option {
	return func(p *Plugin) {
		p.config = cfg
	}
}

// New creates a new Bearer plugin instance.
// Directly accepts the config struct so users can configure it directly (matching Better Auth's plugin pattern),
// with functional options supported as additional optional overrides.
func New(cfg bearerconfig.BearerConfig, opts ...Option) *Plugin {
	p := &Plugin{
		config: cfg,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// ID returns the unique plugin identifier.
func (p *Plugin) ID() string {
	return PluginID
}

// Migrator returns nil as the Bearer plugin does not require database tables.
func (p *Plugin) Migrator() migration.IMigrator {
	return nil
}

// Services returns nil as the Bearer plugin is transport/middleware-only.
func (p *Plugin) Services() map[string]any {
	return nil
}

// Routes returns nil as the Bearer plugin does not expose dedicated routes.
func (p *Plugin) Routes() []plugins.RouteDescriptor {
	return nil
}

// Init registers the Bearer middleware on the Huma API.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	if ictx == nil {
		return fmt.Errorf("bearer plugin: init context is required")
	}
	if ictx.Api == nil {
		return fmt.Errorf("bearer plugin: Huma API is required")
	}

	if !p.config.RequireSignature {
		slog.Warn("bearer: RequireSignature is disabled — unsigned bearer tokens will be accepted; enable it to require HMAC-signed tokens")
	}

	// Register global Huma middleware for request & response interception
	ictx.Api.UseMiddleware(p.Middleware(ictx.Config))

	return nil
}

// Middleware creates the Huma middleware implementing Better Auth's before and after hooks.
func (p *Plugin) Middleware(authCfg config.AuthConfig) func(ctx huma.Context, next func(huma.Context)) {
	cm := cookies.New(authCfg)
	cookieName := cm.Name(cookies.CookieSessionToken)

	return func(ctx huma.Context, next func(huma.Context)) {
		// ─── BEFORE HOOK: Convert Authorization: Bearer <token> to Session Cookie ───
		authHeader := ctx.Header("Authorization")
		if authHeader == "" {
			authHeader = ctx.Header("authorization")
		}

		var bearerToken string
		var hasBearer bool

		if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			raw := strings.TrimSpace(authHeader[7:])
			if raw != "" {
				if tok, ok := VerifyAndExtractToken(raw, authCfg.Secret, p.config.RequireSignature); ok {
					bearerToken = tok
					hasBearer = true
					// Attach raw session token to context
					ctx = huma.WithContext(ctx, humaadapter.WithBearerToken(ctx.Context(), tok))
				}
			}
		}

		var signedCookieVal string
		if hasBearer {
			signedCookieVal = cm.Signed(bearerToken)
		}

		wrapped := &bearerContextWrapper{
			inner:      ctx,
			cookieName: cookieName,
			injectedCookie: func() string {
				if hasBearer {
					return cookieName + "=" + signedCookieVal
				}
				return ""
			}(),
		}

		// Also attach cookie to underlying http.Request if available
		if hasBearer {
			if r, _ := humago.Unwrap(ctx); r != nil {
				existingCookie := r.Header.Get("Cookie")
				if existingCookie == "" {
					r.Header.Set("Cookie", wrapped.injectedCookie)
				} else if !strings.Contains(existingCookie, cookieName+"=") {
					r.Header.Set("Cookie", existingCookie+"; "+wrapped.injectedCookie)
				}
			}
		}

		next(wrapped)

		// ─── AFTER HOOK: Intercept Set-Cookie and set set-auth-token ───
		wrapped.finalizeHeaders()
	}
}

// VerifyAndExtractToken validates and extracts the raw session token from a bearer token string.
// Handles URL-encoded tokens, HMAC-SHA256 signatures (standard base64 & URL-safe base64),
// and raw unsigned tokens (when requireSignature is false).
func VerifyAndExtractToken(token string, secret string, requireSignature bool) (string, bool) {
	if token == "" {
		return "", false
	}
	if strings.Contains(token, "%") {
		if unescaped, err := url.PathUnescape(token); err == nil {
			token = unescaped
		}
	}
	if strings.Contains(token, ".") {
		dot := strings.LastIndex(token, ".")
		rawVal := token[:dot]
		sig := token[dot+1:]
		if rawVal == "" || sig == "" {
			return "", false
		}

		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(rawVal))
		expectedMAC := mac.Sum(nil)

		// 1. Standard base64 padded
		if subtle.ConstantTimeCompare([]byte(sig), []byte(base64.StdEncoding.EncodeToString(expectedMAC))) == 1 {
			return rawVal, true
		}
		// 2. Standard base64 unpadded
		if subtle.ConstantTimeCompare([]byte(sig), []byte(base64.RawStdEncoding.EncodeToString(expectedMAC))) == 1 {
			return rawVal, true
		}
		// 3. URL-safe base64 unpadded (Better Auth base64urlnopad)
		if subtle.ConstantTimeCompare([]byte(sig), []byte(base64.RawURLEncoding.EncodeToString(expectedMAC))) == 1 {
			return rawVal, true
		}
		// 4. URL-safe base64 padded
		if subtle.ConstantTimeCompare([]byte(sig), []byte(base64.URLEncoding.EncodeToString(expectedMAC))) == 1 {
			return rawVal, true
		}
		return "", false
	}

	if requireSignature {
		return "", false
	}
	return token, true
}

type bearerContextWrapper struct {
	inner          huma.Context
	cookieName     string
	injectedCookie string
	setAuthToken   string
}

var _ huma.Context = (*bearerContextWrapper)(nil)

func (w *bearerContextWrapper) Unwrap() huma.Context       { return w.inner }
func (w *bearerContextWrapper) Operation() *huma.Operation { return w.inner.Operation() }
func (w *bearerContextWrapper) Context() context.Context   { return w.inner.Context() }
func (w *bearerContextWrapper) TLS() *tls.ConnectionState  { return w.inner.TLS() }
func (w *bearerContextWrapper) Version() huma.ProtoVersion { return w.inner.Version() }
func (w *bearerContextWrapper) Method() string             { return w.inner.Method() }
func (w *bearerContextWrapper) Host() string               { return w.inner.Host() }
func (w *bearerContextWrapper) RemoteAddr() string         { return w.inner.RemoteAddr() }
func (w *bearerContextWrapper) URL() url.URL               { return w.inner.URL() }
func (w *bearerContextWrapper) Param(name string) string   { return w.inner.Param(name) }
func (w *bearerContextWrapper) Query(name string) string   { return w.inner.Query(name) }
func (w *bearerContextWrapper) BodyReader() io.Reader      { return w.inner.BodyReader() }
func (w *bearerContextWrapper) GetMultipartForm() (*multipart.Form, error) {
	return w.inner.GetMultipartForm()
}
func (w *bearerContextWrapper) SetReadDeadline(t time.Time) error { return w.inner.SetReadDeadline(t) }
func (w *bearerContextWrapper) SetStatus(code int)                { w.inner.SetStatus(code) }
func (w *bearerContextWrapper) Status() int                       { return w.inner.Status() }
func (w *bearerContextWrapper) BodyWriter() io.Writer             { return w.inner.BodyWriter() }

func (w *bearerContextWrapper) Header(name string) string {
	if strings.EqualFold(name, "Cookie") && w.injectedCookie != "" {
		existing := w.inner.Header(name)
		if existing == "" {
			return w.injectedCookie
		}
		if !strings.Contains(existing, w.cookieName+"=") {
			return existing + "; " + w.injectedCookie
		}
		return existing
	}
	return w.inner.Header(name)
}

func (w *bearerContextWrapper) EachHeader(cb func(name, value string)) {
	calledCookie := false
	w.inner.EachHeader(func(name, value string) {
		if strings.EqualFold(name, "Cookie") && w.injectedCookie != "" {
			calledCookie = true
			if !strings.Contains(value, w.cookieName+"=") {
				value = value + "; " + w.injectedCookie
			}
		}
		cb(name, value)
	})
	if !calledCookie && w.injectedCookie != "" {
		cb("Cookie", w.injectedCookie)
	}
}

func (w *bearerContextWrapper) SetHeader(name, value string) {
	w.inner.SetHeader(name, value)
	if strings.EqualFold(name, "Set-Cookie") {
		w.inspectSetCookie(value)
	}
}

func (w *bearerContextWrapper) AppendHeader(name, value string) {
	w.inner.AppendHeader(name, value)
	if strings.EqualFold(name, "Set-Cookie") {
		w.inspectSetCookie(value)
	}
}

func (w *bearerContextWrapper) inspectSetCookie(cookieStr string) {
	parts := strings.Split(cookieStr, ";")
	if len(parts) == 0 {
		return
	}
	kv := strings.SplitN(parts[0], "=", 2)
	if len(kv) != 2 {
		return
	}
	name := strings.TrimSpace(kv[0])
	val := strings.TrimSpace(kv[1])

	if strings.EqualFold(name, w.cookieName) {
		lower := strings.ToLower(cookieStr)
		if strings.Contains(lower, "max-age=0") || strings.Contains(lower, "max-age=-") || strings.Contains(lower, "expires=thu, 01 jan 1970") {
			return
		}
		if val == "" {
			return
		}
		if strings.Contains(val, "%") {
			if unescaped, err := url.PathUnescape(val); err == nil {
				val = unescaped
			}
		}

		w.setAuthToken = val
		w.inner.SetHeader("set-auth-token", val)
		w.addExposedHeader("set-auth-token")

		if _, hw := humago.Unwrap(w.inner); hw != nil {
			hw.Header().Set("set-auth-token", val)
			cur := hw.Header().Get("Access-Control-Expose-Headers")
			hw.Header().Set("Access-Control-Expose-Headers", appendExposed(cur, "set-auth-token"))
		}
	}
}

func (w *bearerContextWrapper) addExposedHeader(hdr string) {
	cur := w.inner.Header("Access-Control-Expose-Headers")
	w.inner.SetHeader("Access-Control-Expose-Headers", appendExposed(cur, hdr))
}

func (w *bearerContextWrapper) finalizeHeaders() {
	if _, hw := humago.Unwrap(w.inner); hw != nil {
		for _, sc := range hw.Header()["Set-Cookie"] {
			w.inspectSetCookie(sc)
		}
	}
}

func appendExposed(current, toAdd string) string {
	if current == "" {
		return toAdd
	}
	parts := strings.Split(current, ",")
	for _, p := range parts {
		if strings.EqualFold(strings.TrimSpace(p), toAdd) {
			return current
		}
	}
	return current + ", " + toAdd
}
