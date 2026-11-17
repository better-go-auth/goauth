package humagenericoauth

import (
	"net/http"
	"time"

	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/providers/ratelimit"
	"github.com/danielgtaylor/huma/v2"
)

// Operation IDs (better-auth's endpoint keys).
const (
	OpSignInWithOAuth2  = "signInWithOAuth2"
	OpOAuth2Callback    = "oAuth2Callback"
	OpOAuth2LinkAccount = "oAuth2LinkAccount"
)

// Register mounts the generic-oauth endpoints.
func Register(kit *pluginkit.Kit, api huma.API, h *Handler) {
	tags := []string{"generic-oauth"}
	// better-auth's default special rule for /sign-in/*: 3 requests per 10 seconds
	signInLimit := &ratelimit.Rule{Window: 10 * time.Second, Max: 3}

	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpSignInWithOAuth2, Method: http.MethodPost, Path: "/sign-in/oauth2",
		Summary: "Sign in with OAuth2", Tags: tags, Access: pluginkit.Public, RateLimit: signInLimit,
	}, h.SignIn)

	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpOAuth2Callback, Method: http.MethodGet, Path: "/oauth2/callback/{providerId}",
		Summary: "OAuth2 callback", Tags: tags, Access: pluginkit.Public, SkipOriginCheck: true, Hidden: true,
	}, h.Callback)

	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpOAuth2LinkAccount, Method: http.MethodPost, Path: "/oauth2/link",
		Summary: "Link an OAuth2 account to the current user session", Tags: tags, Access: pluginkit.Session,
	}, h.Link)
}
