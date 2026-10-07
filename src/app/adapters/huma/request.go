package humaadapter

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"

	authsvc "github.com/better-go-auth/goauth/src/app/services/auth"
	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/danielgtaylor/huma/v2"
)

// requestContext puts a copy of the request in ctx (for config callbacks via config.GetHTTPRequest),
// built from huma.Context so it works with every Huma router adapter.
func (h *handler) requestContext() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		u := ctx.URL()
		req := &http.Request{Method: ctx.Method(), URL: &u, Host: ctx.Host(), RemoteAddr: ctx.RemoteAddr(), Header: http.Header{}}
		ctx.EachHeader(func(name, value string) { req.Header.Add(name, value) })
		req = req.WithContext(ctx.Context())
		next(huma.WithContext(ctx, config.WithHTTPRequest(ctx.Context(), req)))
	}
}

func requestOf(ctx context.Context) *http.Request { return config.GetHTTPRequest(ctx) }

// meta returns the IP and user agent stored on new sessions.
func (h *handler) meta(ctx context.Context) authsvc.Meta {
	req := requestOf(ctx)
	if req == nil {
		return authsvc.Meta{}
	}
	return authsvc.Meta{IPAddress: h.clientIP(req), UserAgent: req.Header.Get("User-Agent")}
}

// clientIP follows Advanced.IPAddress: the configured headers in order (default x-forwarded-for),
// then the connection address. DisableTracking stores no IP.
func (h *handler) clientIP(req *http.Request) string {
	conf := h.Conf.Advanced.IPAddress
	if conf.DisableTracking {
		return ""
	}
	headers := conf.Headers
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
	return func(ctx huma.Context, next func(huma.Context)) {
		switch ctx.Method() {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next(ctx)
			return
		}
		// disableOriginCheck alone also disables the CSRF check, for compatibility with better-auth
		if h.Conf.Advanced.DisableCSRFCheck || h.Conf.Advanced.DisableOriginCheck {
			next(ctx)
			return
		}
		if err := h.validateOrigin(ctx, formCSRF); err != nil {
			writeError(ctx, err)
			return
		}
		next(ctx)
	}
}

func (h *handler) validateOrigin(ctx huma.Context, formCSRF bool) *autherr.AuthError {
	hasCookies := ctx.Header("Cookie") != ""
	force := false
	if formCSRF && !hasCookies {
		site, mode, dest := ctx.Header("Sec-Fetch-Site"), ctx.Header("Sec-Fetch-Mode"), ctx.Header("Sec-Fetch-Dest")
		switch {
		case site != "" || mode != "" || dest != "":
			if site == "cross-site" && mode == "navigate" {
				return autherr.ErrCrossSiteNavigationLoginBlocked
			}
			force = true
		case ctx.Header("Origin") != "" || ctx.Header("Referer") != "":
			force = true
		default:
			// no browser signals at all (curl, server-to-server)
			return nil
		}
	}
	if !hasCookies && !force {
		return nil
	}
	o := ctx.Header("Origin")
	if o == "" {
		o = ctx.Header("Referer")
	}
	if o == "" || o == "null" {
		return autherr.ErrMissingOrNullOrigin
	}
	if !h.Origins.IsTrusted(o, false) {
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
