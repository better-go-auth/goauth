package humaadapter

import (
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/danielgtaylor/huma/v2"
)

// APIErrorReporter installs better-auth's onAPIError handling for one request: errors that better-auth's
// router hands to onError (unexpected errors, origin-check and before-hook failures) go to
// OnAPIError.OnError, or are re-raised as a panic with OnAPIError.Throw. Without either option it is a
// pass-through and goauth logs unexpected errors itself.
func APIErrorReporter(opts config.OnAPIErrorOptions) func(huma.Context, func(huma.Context)) {
	if opts.OnError == nil && !opts.Throw {
		return func(ctx huma.Context, next func(huma.Context)) { next(ctx) }
	}
	return func(ctx huma.Context, next func(huma.Context)) {
		req := requestOf(ctx.Context())
		if req == nil {
			req = httpRequestOf(ctx)
		}
		report := func(err error) {
			// throw wins over onError, like better-auth's router
			if opts.Throw {
				panic(err)
			}
			opts.OnError(err, req)
		}
		next(huma.WithContext(ctx, autherr.WithReporter(ctx.Context(), report)))
	}
}
