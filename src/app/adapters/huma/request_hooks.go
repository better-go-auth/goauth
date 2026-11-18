package humaadapter

import (
	"strings"
	"sync"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/danielgtaylor/huma/v2"
)

// RequestHookSet holds the plugins' request hooks (plugins.RequestHooksProvider, better-auth's plugin
// `onRequest`), added after each plugin's Init. It is safe for concurrent use.
type RequestHookSet struct {
	mu    sync.RWMutex
	hooks []endpointhooks.RequestFunc
}

// NewRequestHookSet returns an empty set.
func NewRequestHookSet() *RequestHookSet { return &RequestHookSet{} }

// Add appends request hooks (plugin order = run order); nil hooks are ignored.
func (s *RequestHookSet) Add(hooks ...endpointhooks.RequestFunc) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range hooks {
		if h != nil {
			s.hooks = append(s.hooks, h)
		}
	}
}

func (s *RequestHookSet) snapshot() []endpointhooks.RequestFunc {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hooks
}

// RequestHooks runs the plugins' request hooks (better-auth's router onRequest loop over plugin.onRequest).
// SetupGoAuth registers it right before the global rate limiter, so the hooks see every core and plugin
// request under BasePath first. The first hook returning a response or an error answers the request.
func RequestHooks(conf config.AuthConfig, set *RequestHookSet) func(huma.Context, func(huma.Context)) {
	basePath := strings.TrimRight(conf.BasePath, "/")
	if conf.BasePath == "" {
		basePath = "/api/auth"
	}
	return func(ctx huma.Context, next func(huma.Context)) {
		// Step 1: only goauth routes, and only when a plugin declared request hooks
		hooks := set.snapshot()
		if len(hooks) == 0 || !underBasePath(ctx, basePath) {
			next(ctx)
			return
		}
		// Step 2: run the hooks in plugin order; the first response or error wins
		req := requestOf(ctx.Context())
		if req == nil {
			req = httpRequestOf(ctx)
		}
		for _, h := range hooks {
			res, err := h(req)
			if err != nil {
				// like better-auth, a failure before the endpoint is reported to onAPIError.onError
				ae := autherr.AsAuthError(err)
				if ae == nil {
					ae = autherr.Internal(ctx.Context(), err)
				}
				autherr.Report(ctx.Context(), err)
				writeError(ctx, ae)
				return
			}
			if res != nil {
				writeHookResponse(ctx, res)
				return
			}
		}
		// Step 3: continue with the rate limiter and the route
		next(ctx)
	}
}

// writeHookResponse writes a hook response (headers, status, body) to ctx.
func writeHookResponse(ctx huma.Context, res *endpointhooks.Response) {
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
