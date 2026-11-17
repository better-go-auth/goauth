// Package humaonetimetoken mounts the one-time-token plugin endpoints on a Huma API.
package humaonetimetoken

import (
	"context"
	"net/http"

	modeldtos "github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins/one-time-token/dtos"
	"github.com/better-go-auth/goauth/src/plugins/one-time-token/services"
)

// Handler adapts OneTimeTokenService to Huma operations.
type Handler struct {
	Service *services.OneTimeTokenService
}

// NewHandler builds the Huma handler.
func NewHandler(svc *services.OneTimeTokenService) *Handler { return &Handler{Service: svc} }

// ─── GET /one-time-token/generate ────────────────────────────────────────────

type generateOutput struct {
	Body dtos.TokenResponse
}

// Generate creates a one-time token for the current session.
func (h *Handler) Generate(ctx context.Context, _ *struct{}) (*generateOutput, error) {
	token, err := h.Service.GenerateForClient(ctx, h.Service.Kit().Current(ctx))
	if err != nil {
		return nil, err
	}
	return &generateOutput{Body: dtos.TokenResponse{Token: token}}, nil
}

// ─── POST /one-time-token/verify ─────────────────────────────────────────────

type verifyInput struct {
	Cookie string `header:"Cookie"`
	Body   struct {
		dtos.VerifyInput
		_ struct{} `json:"-" additionalProperties:"true"`
	}
}

type verifyOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      modeldtos.SessionWithUser
}

// Verify exchanges a one-time token for its session.
func (h *Handler) Verify(ctx context.Context, in *verifyInput) (*verifyOutput, error) {
	kit := h.Service.Kit()
	// Step 1: consume the token
	sw, err := h.Service.Verify(ctx, in.Body.Token)
	if err != nil {
		return nil, err
	}
	// Step 2: set the session cookie (keeping the device's dont_remember choice) unless disabled
	out := &verifyOutput{Body: *sw}
	if !h.Service.Config().DisableSetSessionCookie {
		out.SetCookie = kit.SessionCookies(sw, kit.Cookies.DontRemember(in.Cookie))
	}
	return out, nil
}
