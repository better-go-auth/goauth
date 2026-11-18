package humamagiclink

import (
	"net/http"
	"strings"

	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/providers/ratelimit"
	"github.com/danielgtaylor/huma/v2"
)

// RateLimitRules is better-auth's magic-link rule for goauth's global limiter: paths starting with
// /sign-in/magic-link or /magic-link/verify get rule.
func RateLimitRules(rule ratelimit.Rule) []ratelimit.PathRule {
	return []ratelimit.PathRule{{
		PathMatcher: func(path string) bool {
			return strings.HasPrefix(path, "/sign-in/magic-link") || strings.HasPrefix(path, "/magic-link/verify")
		},
		Window: rule.Window,
		Max:    rule.Max,
	}}
}

// SetupMagicLinkRoutes registers POST /sign-in/magic-link and GET /magic-link/verify (rate limited through
// the plugin's RateLimitRules).
func SetupMagicLinkRoutes(api huma.API, kit *pluginkit.Kit, handler *MagicLinkHandler) {
	tags := []string{"magic-link"}

	// Step 1: sign-in stores the token and sends the link (origin check like any public POST)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: "signInWithMagicLink",
		Method:      http.MethodPost,
		Path:        "/sign-in/magic-link",
		Summary:     "Sign in with magic link",
		Tags:        tags,
		Access:      pluginkit.Public,
	}, handler.SignIn)

	// Step 2: verify is a GET link opened from an email; it validates its own redirect targets
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID:     "verifyMagicLink",
		Method:          http.MethodGet,
		Path:            "/magic-link/verify",
		Summary:         "Verify magic link",
		Tags:            tags,
		Access:          pluginkit.Public,
		SkipOriginCheck: true,
	}, handler.Verify)
}
