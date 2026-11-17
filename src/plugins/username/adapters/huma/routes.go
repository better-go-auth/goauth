package humausername

import (
	"net/http"
	"time"

	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/providers/ratelimit"
	"github.com/danielgtaylor/huma/v2"
)

// Operation IDs (better-auth's endpoint keys), usable in AuthConfig.DisabledOps.
const (
	OpSignInUsername      = "signInUsername"
	OpIsUsernameAvailable = "isUsernameAvailable"
)

// SignInRateLimit is better-auth's default special rule for /sign-in/* paths (10s, 3 requests).
var SignInRateLimit = ratelimit.Rule{Window: 10 * time.Second, Max: 3}

// RegisterRoutes mounts the username endpoints under the kit's base path.
func RegisterRoutes(api huma.API, kit *pluginkit.Kit, h *Handler) {
	tags := []string{"username"}
	signInRule := SignInRateLimit
	// Step 1: username + password sign-in (sign-in CSRF checks, like /sign-in/email)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpSignInUsername, Method: http.MethodPost, Path: SignInPath, Summary: "Sign in with username",
		Tags: tags, Access: pluginkit.Form, RateLimit: &signInRule,
	}, h.SignIn)
	// Step 2: availability check
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpIsUsernameAvailable, Method: http.MethodPost, Path: "/is-username-available",
		Summary: "Check if a username is available", Tags: tags, Access: pluginkit.Public,
	}, h.IsUsernameAvailable)
}
