package humamagiclink

import (
	"net/http"

	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/providers/ratelimit"
	"github.com/danielgtaylor/huma/v2"
)

// SetupMagicLinkRoutes registers POST /sign-in/magic-link and GET /magic-link/verify with the given rate limit rule.
func SetupMagicLinkRoutes(api huma.API, kit *pluginkit.Kit, handler *MagicLinkHandler, rule ratelimit.Rule) {
	tags := []string{"magic-link"}

	// Step 1: sign-in stores the token and sends the link (origin check like any public POST)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: "signInWithMagicLink",
		Method:      http.MethodPost,
		Path:        "/sign-in/magic-link",
		Summary:     "Sign in with magic link",
		Tags:        tags,
		Access:      pluginkit.Public,
		RateLimit:   &rule,
	}, handler.SignIn)

	// Step 2: verify is a GET link opened from an email; it validates its own redirect targets
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID:     "verifyMagicLink",
		Method:          http.MethodGet,
		Path:            "/magic-link/verify",
		Summary:         "Verify magic link",
		Tags:            tags,
		Access:          pluginkit.Public,
		RateLimit:       &rule,
		SkipOriginCheck: true,
	}, handler.Verify)
}
