package humaadapter

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"

	svcint "github.com/better-go-auth/goauth/src/app/services/interfaces"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/providers/origin"
	"github.com/danielgtaylor/huma/v2"
)

// requestContext puts a copy of the request in ctx (for config callbacks via config.GetHTTPRequest),
// built from huma.Context so it works with every Huma router adapter.
func (h *handler) requestContext() func(huma.Context, func(huma.Context)) {
	return RequestContext()
}

// RequestContext is the exported request-context middleware, shared with plugin routes so
// config.GetHTTPRequest(ctx) works in every goauth handler.
func RequestContext() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		// always rebuild: transport middlewares (bearer) may have rewritten headers since an earlier copy
		u := ctx.URL()
		req := &http.Request{Method: ctx.Method(), URL: &u, Host: ctx.Host(), RemoteAddr: ctx.RemoteAddr(), Header: http.Header{}}
		ctx.EachHeader(func(name, value string) { req.Header.Add(name, value) })
		req = req.WithContext(ctx.Context())
		c := config.WithHTTPRequest(ctx.Context(), req)
		// keep a proxy-assigned request ID so internal errors are logged under the same ID
		c = autherr.WithRequestID(c, ctx.Header(autherr.RequestIDHeader))
		next(huma.WithContext(ctx, c))
	}
}

func requestOf(ctx context.Context) *http.Request { return config.GetHTTPRequest(ctx) }

// meta returns the IP and user agent stored on new sessions.
func (h *handler) meta(ctx context.Context) svcint.Meta {
	req := requestOf(ctx)
	if req == nil {
		return svcint.Meta{}
	}
	return svcint.Meta{IPAddress: h.clientIP(req), UserAgent: req.Header.Get("User-Agent")}
}

// clientIP follows Advanced.IPAddress: the configured headers in order (default x-forwarded-for),
// then the connection address. DisableTracking stores no IP.
func (h *handler) clientIP(req *http.Request) string {
	return ClientIP(h.Conf, req)
}

// SessionMeta returns the IP and user agent stored on new sessions, for plugin handlers.
func SessionMeta(conf config.AuthConfig, ctx context.Context) svcint.Meta {
	req := requestOf(ctx)
	if req == nil {
		return svcint.Meta{}
	}
	return svcint.Meta{IPAddress: ClientIP(conf, req), UserAgent: req.Header.Get("User-Agent")}
}

// ClientIP resolves the client IP following Advanced.IPAddress (exported for plugins and rate limiting).
func ClientIP(conf config.AuthConfig, req *http.Request) string {
	if req == nil {
		return ""
	}
	ipConf := conf.Advanced.IPAddress
	if ipConf.DisableTracking {
		return ""
	}
	headers := ipConf.Headers
	if len(headers) == 0 {
		headers = []string{"x-forwarded-for"}
	}
	for _, name := range headers {
		first, _, _ := strings.Cut(req.Header.Get(name), ",")
		if ip := net.ParseIP(strings.TrimSpace(first)); ip != nil {
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return ""
}

// originCheck is better-auth's originCheckMiddleware for mutating requests: requests carrying cookies must
// come from a trusted Origin/Referer. With formCSRF (sign-in/sign-up) cookieless browser requests are checked
// too, using Fetch Metadata, and cross-site navigations are blocked.
func (h *handler) originCheck(formCSRF bool) func(huma.Context, func(huma.Context)) {
	return OriginCheck(h.Conf, h.Origins, formCSRF)
}

// OriginCheck is the exported origin/CSRF middleware, shared with plugin routes.
func OriginCheck(conf config.AuthConfig, origins *origin.Checker, formCSRF bool) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		if err := OriginError(ctx, conf, origins, formCSRF); err != nil {
			writeError(ctx, err)
			return
		}
		next(ctx)
	}
}

// OriginError validates Origin/Referer headers on mutating requests when CSRF/origin checks are enabled.
func OriginError(ctx huma.Context, conf config.AuthConfig, origins *origin.Checker, formCSRF bool) *autherr.AuthError {
	// 1. Skip safe read/preflight HTTP methods
	switch ctx.Method() {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return nil
	}
	// 2. disableOriginCheck alone also disables the CSRF check, for compatibility with better-auth
	if conf.Advanced.DisableCSRFCheck || conf.Advanced.DisableOriginCheck {
		return nil
	}
	// 3. Non-browser Bearer requests without Origin/Referer bypass cookie CSRF checks
	if authHeader := ctx.Header("Authorization"); strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		o := ctx.Header("Origin")
		if o == "" {
			o = ctx.Header("Referer")
		}
		if o == "" {
			return nil
		}
	}
	return validateOrigin(ctx, origins, formCSRF)
}

func validateOrigin(ctx huma.Context, origins *origin.Checker, formCSRF bool) *autherr.AuthError {
	req := requestOf(ctx.Context())
	var hasCookies bool
	if req != nil {
		hasCookies = req.Header.Get("Cookie") != ""
	} else {
		hasCookies = ctx.Header("Cookie") != ""
	}

	o := ctx.Header("Origin")
	if o == "" {
		o = ctx.Header("Referer")
	}

	force := false
	if formCSRF && !hasCookies {
		site, mode, dest := ctx.Header("Sec-Fetch-Site"), ctx.Header("Sec-Fetch-Mode"), ctx.Header("Sec-Fetch-Dest")
		switch {
		case site != "" || mode != "" || dest != "":
			if site == "cross-site" && mode == "navigate" {
				return autherr.ErrCrossSiteNavigationLoginBlocked
			}
			force = true
		case o != "":
			force = true
		default:
			// no browser signals at all (curl, server-to-server)
			return nil
		}
	}
	if !hasCookies && !force && o == "" {
		return nil
	}
	if o == "" || o == "null" {
		return autherr.ErrMissingOrNullOrigin
	}
	if origins != nil && !origins.IsTrusted(o, false) {
		return autherr.ErrInvalidOrigin
	}
	return nil
}

// checkURL validates a client-supplied redirect target against the trusted origins (relative paths allowed).
func (h *handler) checkURL(raw string, invalid *autherr.AuthError) error {
	if raw == "" || h.Conf.Advanced.DisableOriginCheck {
		return nil
	}
	if !h.Origins.IsTrusted(raw, true) {
		return invalid
	}
	return nil
}

func (h *handler) checkCallbackURL(raw *string) error {
	if raw == nil {
		return nil
	}
	return h.checkURL(*raw, autherr.ErrInvalidCallbackURL)
}

// resolveRedirect is better-auth's redirectCallback: callbackURL resolved against <BaseURL><BasePath>,
// with query parameters set.
func (h *handler) resolveRedirect(callbackURL string, query map[string]string) string {
	base, err := url.Parse(strings.TrimRight(h.Conf.BaseURL, "/") + h.Conf.BasePath)
	if err != nil {
		return callbackURL
	}
	target, err := base.Parse(callbackURL)
	if err != nil {
		return callbackURL
	}
	q := target.Query()
	for k, v := range query {
		q.Set(k, v)
	}
	target.RawQuery = q.Encode()
	return target.String()
}

// errorRedirect is better-auth's redirectError: callbackURL (or <base>/error) with ?error=CODE.
func (h *handler) errorRedirect(callbackURL, code string) string {
	if callbackURL == "" {
		callbackURL = strings.TrimRight(h.Conf.BaseURL, "/") + h.Conf.BasePath + "/error"
	}
	return h.resolveRedirect(callbackURL, map[string]string{"error": code})
}

// errorCode returns the better-auth code of err, or INTERNAL_SERVER_ERROR.
func errorCode(err error) string {
	if ae := autherr.AsAuthError(err); ae != nil {
		return string(ae.Code)
	}
	return "INTERNAL_SERVER_ERROR"
}
