package humasocial

import (
	"net/http"
	"time"

	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/providers/ratelimit"
	"github.com/danielgtaylor/huma/v2"
)

// Operation IDs (better-auth's operationId where it has one).
const (
	OpSocialSignIn         = "socialSignIn"
	OpHandleOAuthCallback  = "handleOAuthCallback"
	OpHandleOAuthCallbackP = "handleOAuthCallbackPost"
	OpLinkSocialAccount    = "linkSocialAccount"
	OpGetAccessToken       = "getAccessToken"
	OpRefreshToken         = "refreshToken"
	OpAccountInfo          = "accountInfo"
)

// Register mounts the social endpoints.
func Register(kit *pluginkit.Kit, api huma.API, h *Handler) {
	tags := []string{"social"}
	// better-auth's default special rule for /sign-in/*: 3 requests per 10 seconds
	signInLimit := &ratelimit.Rule{Window: 10 * time.Second, Max: 3}

	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpSocialSignIn, Method: http.MethodPost, Path: "/sign-in/social",
		Summary: "Sign in with a social provider", Tags: tags, Access: pluginkit.Public, RateLimit: signInLimit,
	}, h.SignInSocial)

	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpHandleOAuthCallback, Method: http.MethodGet, Path: "/callback/{id}",
		Summary: "OAuth callback", Tags: tags, Access: pluginkit.Public, SkipOriginCheck: true, Hidden: true,
	}, h.Callback)

	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpHandleOAuthCallbackP, Method: http.MethodPost, Path: "/callback/{id}",
		Summary: "OAuth callback (form_post)", Tags: tags, Access: pluginkit.Public, Hidden: true,
	}, h.CallbackPost)

	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpLinkSocialAccount, Method: http.MethodPost, Path: "/link-social",
		Summary: "Link a social account to the user", Tags: tags, Access: pluginkit.Session,
	}, h.LinkSocial)

	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpGetAccessToken, Method: http.MethodPost, Path: "/get-access-token",
		Summary: "Get a valid access token, doing a refresh if needed", Tags: tags, Access: pluginkit.OptionalSession,
	}, h.GetAccessToken)

	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpRefreshToken, Method: http.MethodPost, Path: "/refresh-token",
		Summary: "Refresh the access token using a refresh token", Tags: tags, Access: pluginkit.OptionalSession,
	}, h.RefreshToken)

	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpAccountInfo, Method: http.MethodGet, Path: "/account-info",
		Summary: "Get the account info provided by the provider", Tags: tags, Access: pluginkit.OptionalSession,
	}, h.AccountInfo)
}
