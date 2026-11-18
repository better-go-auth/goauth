package humaanonymous

import (
	"net/http"

	"github.com/better-go-auth/goauth/src/plugins/anonymous/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/danielgtaylor/huma/v2"
)

// Operation IDs (better-auth's endpoint keys), usable in AuthConfig.DisabledOps.
const (
	OpSignInAnonymous     = "signInAnonymous"
	OpDeleteAnonymousUser = "deleteAnonymousUser"
)

// RegisterRoutes mounts the anonymous endpoints under the kit's base path. Sign-in is rate limited by the
// global limiter's /sign-in special rule (3 requests per 10 s).
func RegisterRoutes(api huma.API, kit *pluginkit.Kit, h *Handler) {
	tags := []string{"anonymous"}
	// Step 1: anonymous sign-in sees the current session (anonymous users can't sign in again)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpSignInAnonymous, Method: http.MethodPost, Path: services.SignInPath, Summary: "Sign in anonymously",
		Tags: tags, Access: pluginkit.OptionalSession, FormCSRF: true,
	}, h.SignIn)
	// Step 2: deleting requires a fresh session (better-auth's sensitiveSessionMiddleware)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpDeleteAnonymousUser, Method: http.MethodPost, Path: "/delete-anonymous-user",
		Summary: "Delete an anonymous user", Tags: tags, Access: pluginkit.FreshSession,
	}, h.DeleteAnonymousUser)
}
