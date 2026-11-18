package humausername

import (
	"net/http"

	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/danielgtaylor/huma/v2"
)

// Operation IDs (better-auth's endpoint keys), usable in AuthConfig.DisabledOps.
const (
	OpSignInUsername      = "signInUsername"
	OpIsUsernameAvailable = "isUsernameAvailable"
)

// RegisterRoutes mounts the username endpoints under the kit's base path. Sign-in is rate limited by the
// global limiter's /sign-in special rule (3 requests per 10 s).
func RegisterRoutes(api huma.API, kit *pluginkit.Kit, h *Handler) {
	tags := []string{"username"}
	// Step 1: username + password sign-in (sign-in CSRF checks, like /sign-in/email)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpSignInUsername, Method: http.MethodPost, Path: SignInPath, Summary: "Sign in with username",
		Tags: tags, Access: pluginkit.Form,
	}, h.SignIn)
	// Step 2: availability check
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpIsUsernameAvailable, Method: http.MethodPost, Path: "/is-username-available",
		Summary: "Check if a username is available", Tags: tags, Access: pluginkit.Public,
	}, h.IsUsernameAvailable)
}
