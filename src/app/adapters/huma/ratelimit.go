package humaadapter

import (
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/better-go-auth/goauth/src/common/logger"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/providers/ratelimit"
	"github.com/danielgtaylor/huma/v2"
)

// ipWarningLogged makes the "no client IP" warning appear once per process, like better-auth.
var ipWarningLogged atomic.Bool

// RateLimit is goauth's global rate-limit middleware (better-auth's onRequestRateLimit /
// onResponseRateLimit). SetupGoAuth registers it before every other goauth middleware, so it covers every
// core and plugin route under BasePath. A limited request is answered with better-auth's exact response:
//
//	429 Too Many Requests
//	X-Retry-After: <seconds>
//	Content-Type: text/plain;charset=UTF-8
//
//	{"message":"Too many requests. Please try again later."}
//
// Every other request is counted after it was answered.
func RateLimit(conf config.AuthConfig, l *ratelimit.Limiter) func(huma.Context, func(huma.Context)) {
	basePath := strings.TrimRight(conf.BasePath, "/")
	if conf.BasePath == "" {
		basePath = "/api/auth"
	}
	return func(ctx huma.Context, next func(huma.Context)) {
		// Step 1: only enabled limiters, only goauth routes
		if !l.Enabled() || !underBasePath(ctx, basePath) {
			next(ctx)
			return
		}
		// Step 2: client IP (Advanced.IPAddress), normalized like better-auth (IPv6 grouped by subnet)
		req := requestOf(ctx.Context())
		if req == nil {
			req = httpRequestOf(ctx)
		}
		ip := ClientIP(conf, req)
		if ip != "" {
			ip = ratelimit.NormalizeIP(ip, conf.Advanced.IPAddress.IPv6Subnet)
		} else if ipWarningLogged.CompareAndSwap(false, true) {
			logger.Warn("Rate limiting skipped: could not determine client IP address. Ensure your runtime " +
				"forwards a trusted client IP header and configure `Advanced.IPAddress.Headers` if needed.")
		}
		// Step 3: the rule for this path (special, plugin and custom rules); none = not limited
		key, rule, ok := l.Resolve(req, ip)
		if !ok {
			next(ctx)
			return
		}
		// Step 4: reject when the stored record is at its limit inside the window
		if limited, retryAfter := l.Check(ctx.Context(), key, rule); limited {
			ctx.SetHeader(ratelimit.RetryAfterHeader, strconv.Itoa(retryAfter))
			ctx.SetHeader("Content-Type", "text/plain;charset=UTF-8")
			ctx.SetStatus(429)
			_, _ = ctx.BodyWriter().Write([]byte(`{"message":"` + ratelimit.TooManyRequestsMessage + `"}`))
			return
		}
		// Step 5: answer the request, then count it
		next(ctx)
		l.Hit(ctx.Context(), key, rule)
	}
}
