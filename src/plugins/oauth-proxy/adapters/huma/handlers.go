// Package humaoauthproxy mounts the oauth-proxy endpoint on a Huma API.
package humaoauthproxy

import (
	"context"
	"net/http"

	"github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/plugins/oauth-proxy/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/danielgtaylor/huma/v2"
)

// OpOAuthProxyCallback is better-auth's operation ID, usable in AuthConfig.DisabledOps.
const OpOAuthProxyCallback = "oauthProxyCallback"

// Handler adapts the service to Huma.
type Handler struct {
	Service *services.Service
}

// NewHandler builds the handler.
func NewHandler(svc *services.Service) *Handler { return &Handler{Service: svc} }

type callbackInput struct {
	CallbackURL string `query:"callbackURL" required:"true" doc:"The URL to redirect to after the proxy"`
	Profile     string `query:"profile" doc:"Encrypted OAuth profile data"`
}

type redirectOutput struct {
	Status    int
	Location  string        `header:"Location"`
	SetCookie []http.Cookie `header:"Set-Cookie"`
}

// Callback is GET /oauth-proxy-callback: it signs the user in from the encrypted profile and redirects.
func (h *Handler) Callback(ctx context.Context, in *callbackInput) (*redirectOutput, error) {
	// Step 1: the callbackURL must be trusted (better-auth's originCheck(ctx => ctx.query.callbackURL))
	if err := h.Service.Kit().CheckURL(in.CallbackURL, autherr.ErrInvalidCallbackURL); err != nil {
		return nil, err
	}
	// Step 2: every outcome is a redirect
	r, err := h.Service.Callback(ctx, in.Profile)
	if err != nil {
		return nil, err
	}
	return &redirectOutput{Status: http.StatusFound, Location: r.Location, SetCookie: r.Cookies}, nil
}

// RegisterRoutes mounts GET /oauth-proxy-callback under the kit's base path.
func RegisterRoutes(api huma.API, kit *pluginkit.Kit, h *Handler) {
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpOAuthProxyCallback, Method: http.MethodGet, Path: "/oauth-proxy-callback",
		Summary: "OAuth Proxy Callback", Tags: []string{"oauth-proxy"}, Access: pluginkit.Public,
	}, h.Callback)
}
