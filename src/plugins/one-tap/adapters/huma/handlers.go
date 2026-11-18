// Package humaonetap mounts the one-tap plugin endpoint on a Huma API.
package humaonetap

import (
	"context"
	"net/http"

	"github.com/better-go-auth/goauth/src/plugins/one-tap/dtos"
	"github.com/better-go-auth/goauth/src/plugins/one-tap/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/danielgtaylor/huma/v2"
)

// OpOneTapCallback is better-auth's endpoint key, usable in AuthConfig.DisabledOps.
const OpOneTapCallback = "oneTapCallback"

// Handler adapts the one-tap service to Huma operations.
type Handler struct {
	Service *services.Service
}

// NewHandler builds the Huma handler.
func NewHandler(svc *services.Service) *Handler { return &Handler{Service: svc} }

type callbackInput struct {
	Body dtos.CallbackInput
}

type callbackOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      dtos.CallbackResponse
}

// Callback verifies the Google ID token and sets the session cookie.
func (h *Handler) Callback(ctx context.Context, in *callbackInput) (*callbackOutput, error) {
	// Step 1: verify and sign in / link / sign up
	res, err := h.Service.Callback(ctx, in.Body.IDToken)
	if err != nil {
		return nil, err
	}
	// Step 2: the session cookie (better-auth's setSessionCookie) when a session was created
	out := &callbackOutput{Body: res.Body}
	if res.Session != nil {
		out.SetCookie = h.Service.Kit().SessionCookies(res.Session, false)
	}
	return out, nil
}

// RegisterRoutes mounts POST /one-tap/callback under the kit's base path.
func RegisterRoutes(api huma.API, kit *pluginkit.Kit, h *Handler) {
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpOneTapCallback, Method: http.MethodPost, Path: "/one-tap/callback",
		Summary: "Use this endpoint to authenticate with Google One Tap", Tags: []string{"one-tap"},
		Access: pluginkit.Public,
	}, h.Callback)
}
