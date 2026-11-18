package plugins

import (
	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/providers/ratelimit"
)

// RateLimitProvider is an optional interface for plugins that declare rate-limit rules (better-auth's plugin
// `rateLimit` array). SetupGoAuth reads it after the plugin's Init, in plugin order; the first plugin rule
// whose matcher accepts the request path wins over the special rules, and RateLimit.CustomRules win over it.
// The rules only apply while the global limiter is enabled (AuthConfig.RateLimit.Enabled).
type RateLimitProvider interface {
	RateLimitRules() []ratelimit.PathRule
}

// EndpointHooksProvider is an optional interface for plugins with endpoint hooks (better-auth's plugin
// `hooks: {before, after}`). SetupGoAuth reads it after the plugin's Init; the hooks run in plugin order,
// after the user's AuthConfig.Hooks.
type EndpointHooksProvider interface {
	EndpointHooks() endpointhooks.Hooks
}

// RequestHooksProvider is an optional interface for plugins that inspect requests before goauth handles
// them (better-auth's plugin `onRequest`, e.g. captcha). SetupGoAuth reads it after the plugin's Init; the
// hooks run in plugin order before the rate limiter and every other middleware, and the first response or
// error answers the request.
type RequestHooksProvider interface {
	RequestHooks() []endpointhooks.RequestFunc
}
