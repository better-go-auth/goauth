// Package humagenericoauth mounts the generic-oauth endpoints on a Huma API.
package humagenericoauth

import (
	"context"
	"net/http"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	godtos "github.com/better-go-auth/goauth/src/plugins/generic-oauth/dtos"
	"github.com/better-go-auth/goauth/src/plugins/generic-oauth/services"
)

// Handler adapts the generic-oauth service to Huma.
type Handler struct {
	Service *services.Service
}

// NewHandler builds the handler.
func NewHandler(svc *services.Service) *Handler { return &Handler{Service: svc} }

type startOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      godtos.RedirectResponse
}

// ─── POST /sign-in/oauth2 ────────────────────────────────────────────────────

type signInInput struct {
	Body godtos.SignInOAuth2Input
}

// SignIn answers {url, redirect} and sets the OAuth state cookie.
func (h *Handler) SignIn(ctx context.Context, in *signInInput) (*startOutput, error) {
	// Step 1: client supplied redirect targets must be trusted (better-auth's originCheckMiddleware)
	kit := h.Service.Kit()
	for _, c := range []struct {
		url string
		err *autherr.AuthError
	}{
		{in.Body.CallbackURL, autherr.ErrInvalidCallbackURL},
		{in.Body.ErrorCallbackURL, autherr.ErrInvalidErrorCallbackURL},
		{in.Body.NewUserCallbackURL, autherr.ErrInvalidNewUserCallbackURL},
	} {
		if err := kit.CheckURL(c.url, c.err); err != nil {
			return nil, err
		}
	}
	// Step 2: run the flow
	res, err := h.Service.SignIn(ctx, in.Body)
	if err != nil {
		return nil, err
	}
	return &startOutput{SetCookie: res.Cookies, Body: res.Body}, nil
}

// ─── POST /oauth2/link ───────────────────────────────────────────────────────

type linkInput struct {
	Body godtos.OAuth2LinkInput
}

// Link starts linking a provider account to the signed-in user.
func (h *Handler) Link(ctx context.Context, in *linkInput) (*startOutput, error) {
	// Step 1: trusted redirect targets
	kit := h.Service.Kit()
	if err := kit.CheckURL(in.Body.CallbackURL, autherr.ErrInvalidCallbackURL); err != nil {
		return nil, err
	}
	if err := kit.CheckURL(in.Body.ErrorCallbackURL, autherr.ErrInvalidErrorCallbackURL); err != nil {
		return nil, err
	}
	// Step 2: the session user (the route requires a session)
	current := kit.Current(ctx)
	if current == nil {
		return nil, autherr.ErrUnauthorized
	}
	// Step 3: run the flow
	res, err := h.Service.Link(ctx, current, in.Body)
	if err != nil {
		return nil, err
	}
	return &startOutput{SetCookie: res.Cookies, Body: res.Body}, nil
}

// ─── GET /oauth2/callback/{providerId} ───────────────────────────────────────

type callbackInput struct {
	ProviderID       string `path:"providerId"`
	Code             string `query:"code"`
	Error            string `query:"error"`
	ErrorDescription string `query:"error_description"`
	State            string `query:"state"`
	Iss              string `query:"iss"`
}

type redirectOutput struct {
	Status    int
	Location  string        `header:"Location"`
	SetCookie []http.Cookie `header:"Set-Cookie"`
}

// Callback is the provider's redirect target: it finishes the sign-in or link flow and redirects.
func (h *Handler) Callback(ctx context.Context, in *callbackInput) (*redirectOutput, error) {
	r, err := h.Service.Callback(ctx, in.ProviderID, services.CallbackParams{
		Code: in.Code, Error: in.Error, ErrorDescription: in.ErrorDescription, State: in.State, Iss: in.Iss,
	})
	if err != nil {
		return nil, err
	}
	return &redirectOutput{Status: http.StatusFound, Location: r.Location, SetCookie: r.Cookies}, nil
}
