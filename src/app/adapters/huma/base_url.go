package humaadapter

import (
	"net/http"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/logger"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/danielgtaylor/huma/v2"
)

// ErrHostNotAllowed answers requests whose host is not in DynamicBaseURL.AllowedHosts when no fallback is
// configured (better-auth throws a BetterAuthError there; goauth answers 400 instead of an unhandled 500).
var ErrHostNotAllowed = autherr.New("HOST_NOT_ALLOWED", "Host is not in the allowed hosts list", http.StatusBadRequest)

// DynamicBaseURL is better-auth's per-request base URL resolution (baseURL: {allowedHosts, fallback,
// protocol}): it resolves the request's origin from Host / X-Forwarded-Host and stores it in the context, so
// redirects, email links, OAuth callback URLs and trusted origins use the host the request came to. It must
// run after RequestContext. Without AuthConfig.DynamicBaseURL it is a no-op.
func DynamicBaseURL(conf config.AuthConfig) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		// Step 1: static base URL: nothing to resolve
		if conf.DynamicBaseURL == nil {
			next(ctx)
			return
		}
		// Step 2: resolve from the request (fallback when the host is not allowed)
		origin, err := conf.ResolveBaseURL(config.GetHTTPRequest(ctx.Context()))
		if err != nil {
			logger.Warn("goauth: request host rejected by DynamicBaseURL.AllowedHosts", "err", err)
			writeError(ctx, ErrHostNotAllowed)
			return
		}
		// Step 3: every handler reads it through AuthConfig.RequestBaseURL / AuthBaseURL
		next(huma.WithContext(ctx, config.WithRequestBaseURL(ctx.Context(), origin)))
	}
}
