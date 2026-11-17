// Package humaanonymous mounts the anonymous plugin endpoints on a Huma API.
package humaanonymous

import (
	"context"
	"net/http"

	"github.com/better-go-auth/goauth/src/plugins/anonymous/dtos"
	"github.com/better-go-auth/goauth/src/plugins/anonymous/services"
)

// Handler adapts the anonymous Service to Huma operations.
type Handler struct {
	Service *services.Service
}

// NewHandler builds the Huma handler.
func NewHandler(svc *services.Service) *Handler { return &Handler{Service: svc} }

// ─── POST /sign-in/anonymous ─────────────────────────────────────────────────

type signInInput struct {
	Body *struct {
		_ struct{} `json:"-" additionalProperties:"true"`
	} `required:"false"`
}

type signInOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      dtos.SignInAnonymousResponse
}

// SignIn creates an anonymous user and signs it in.
func (h *Handler) SignIn(ctx context.Context, _ *signInInput) (*signInOutput, error) {
	kit := h.Service.Kit()
	// Step 1: create the user and its session
	sw, err := h.Service.SignIn(ctx)
	if err != nil {
		return nil, err
	}
	// Step 2: session cookies and better-auth's {token, user}
	return &signInOutput{
		SetCookie: kit.SessionCookies(sw, false),
		Body:      dtos.SignInAnonymousResponse{Token: sw.Session.Token, User: sw.User},
	}, nil
}

// ─── POST /delete-anonymous-user ─────────────────────────────────────────────

type deleteInput struct {
	Body *struct {
		_ struct{} `json:"-" additionalProperties:"true"`
	} `required:"false"`
}

type deleteOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      dtos.SuccessResponse
}

// DeleteAnonymousUser deletes the signed-in anonymous user and clears the session cookies.
func (h *Handler) DeleteAnonymousUser(ctx context.Context, _ *deleteInput) (*deleteOutput, error) {
	if err := h.Service.DeleteAnonymousUser(ctx); err != nil {
		return nil, err
	}
	return &deleteOutput{
		SetCookie: h.Service.Kit().ExpireSessionCookies(false),
		Body:      dtos.SuccessResponse{Success: true},
	}, nil
}
