// Package humasocial mounts the social sign-in endpoints on a Huma API.
package humasocial

import (
	"context"
	"encoding/json"
	"mime"
	"net/http"
	"net/url"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	socialdtos "github.com/better-go-auth/goauth/src/plugins/social/dtos"
	"github.com/better-go-auth/goauth/src/plugins/social/services"
)

// Handler adapts the social service to Huma.
type Handler struct {
	Service *services.Service
}

// NewHandler builds the handler.
func NewHandler(svc *services.Service) *Handler { return &Handler{Service: svc} }

// ─── POST /sign-in/social ────────────────────────────────────────────────────

type signInSocialInput struct {
	Body socialdtos.SignInSocialInput
}

type signInSocialOutput struct {
	Location  string        `header:"Location"`
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      socialdtos.SignInSocialResponse
}

// SignInSocial answers {url, redirect} (+ Location and the state cookie) or, for an idToken, the session.
func (h *Handler) SignInSocial(ctx context.Context, in *signInSocialInput) (*signInSocialOutput, error) {
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
	res, err := h.Service.SignInSocial(ctx, in.Body)
	if err != nil {
		return nil, err
	}
	return &signInSocialOutput{Location: res.Location, SetCookie: res.Cookies, Body: res.Body}, nil
}

// ─── POST /link-social ───────────────────────────────────────────────────────

type linkSocialInput struct {
	Body socialdtos.LinkSocialInput
}

type linkSocialOutput struct {
	Location  string        `header:"Location"`
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      socialdtos.LinkSocialResponse
}

// LinkSocial starts linking a provider account to the signed-in user.
func (h *Handler) LinkSocial(ctx context.Context, in *linkSocialInput) (*linkSocialOutput, error) {
	// Step 1: trusted redirect targets
	kit := h.Service.Kit()
	if err := kit.CheckURL(in.Body.CallbackURL, autherr.ErrInvalidCallbackURL); err != nil {
		return nil, err
	}
	if err := kit.CheckURL(in.Body.ErrorCallbackURL, autherr.ErrInvalidErrorCallbackURL); err != nil {
		return nil, err
	}
	// Step 2: the session user
	current := kit.Current(ctx)
	if current == nil {
		return nil, autherr.ErrUnauthorized
	}
	// Step 3: run the flow
	res, err := h.Service.LinkSocial(ctx, current, in.Body)
	if err != nil {
		return nil, err
	}
	return &linkSocialOutput{Location: res.Location, SetCookie: res.Cookies, Body: res.Body}, nil
}

// ─── GET|POST /callback/{id} ─────────────────────────────────────────────────

type callbackQuery struct {
	ID               string `path:"id"`
	Code             string `query:"code"`
	Error            string `query:"error"`
	DeviceID         string `query:"device_id"`
	ErrorDescription string `query:"error_description"`
	State            string `query:"state"`
	User             string `query:"user"`
}

func (q callbackQuery) params() services.CallbackParams {
	return services.CallbackParams{Code: q.Code, Error: q.Error, DeviceID: q.DeviceID, ErrorDescription: q.ErrorDescription, State: q.State, User: q.User}
}

type callbackPostInput struct {
	ID               string `path:"id"`
	Code             string `query:"code"`
	Error            string `query:"error"`
	DeviceID         string `query:"device_id"`
	ErrorDescription string `query:"error_description"`
	State            string `query:"state"`
	User             string `query:"user"`
	ContentType      string `header:"Content-Type"`
	RawBody          []byte
}

type redirectOutput struct {
	Status    int
	Location  string        `header:"Location"`
	SetCookie []http.Cookie `header:"Set-Cookie"`
}

func redirect(r *services.Redirect) *redirectOutput {
	return &redirectOutput{Status: http.StatusFound, Location: r.Location, SetCookie: r.Cookies}
}

// Callback is the provider's redirect target: it finishes the sign-in or link flow and redirects.
func (h *Handler) Callback(ctx context.Context, in *callbackQuery) (*redirectOutput, error) {
	return redirect(h.Service.Callback(ctx, in.ID, in.params())), nil
}

// CallbackPost handles response_mode=form_post providers (Apple) by redirecting to the GET callback.
func (h *Handler) CallbackPost(ctx context.Context, in *callbackPostInput) (*redirectOutput, error) {
	// Step 1: the body is form-encoded (form_post) or JSON
	var body services.CallbackParams
	mt, _, _ := mime.ParseMediaType(in.ContentType)
	if mt == "application/json" {
		_ = json.Unmarshal(in.RawBody, &body)
	} else if vals, err := url.ParseQuery(string(in.RawBody)); err == nil {
		body = services.CallbackParams{
			Code: vals.Get("code"), Error: vals.Get("error"), DeviceID: vals.Get("device_id"),
			ErrorDescription: vals.Get("error_description"), State: vals.Get("state"), User: vals.Get("user"),
		}
	}
	// Step 2: redirect to the GET callback with body + query merged
	query := callbackQuery{Code: in.Code, Error: in.Error, DeviceID: in.DeviceID, ErrorDescription: in.ErrorDescription, State: in.State, User: in.User}
	return redirect(h.Service.PostCallbackRedirect(in.ID, body, query.params())), nil
}

// ─── Account tokens ──────────────────────────────────────────────────────────

type accountTokenInput struct {
	Body socialdtos.AccountTokenInput
}

type accessTokenOutput struct {
	Body *socialdtos.AccessTokenResponse
}

// GetAccessToken returns a valid provider access token, refreshing it when needed.
func (h *Handler) GetAccessToken(ctx context.Context, in *accountTokenInput) (*accessTokenOutput, error) {
	res, err := h.Service.GetAccessToken(ctx, in.Body)
	if err != nil {
		return nil, err
	}
	return &accessTokenOutput{Body: res}, nil
}

type refreshTokenOutput struct {
	Body *socialdtos.RefreshTokenResponse
}

// RefreshToken refreshes the provider tokens.
func (h *Handler) RefreshToken(ctx context.Context, in *accountTokenInput) (*refreshTokenOutput, error) {
	res, err := h.Service.RefreshToken(ctx, in.Body)
	if err != nil {
		return nil, err
	}
	return &refreshTokenOutput{Body: res}, nil
}

type accountInfoInput struct {
	AccountID  string `query:"accountId"`
	ProviderID string `query:"providerId"`
	UserID     string `query:"userId"`
}

type accountInfoOutput struct {
	Body *socialdtos.AccountInfoResponse
}

// AccountInfo returns the provider's profile of one of the user's accounts.
func (h *Handler) AccountInfo(ctx context.Context, in *accountInfoInput) (*accountInfoOutput, error) {
	res, err := h.Service.AccountInfo(ctx, services.AccountInfoQuery{AccountID: in.AccountID, ProviderID: in.ProviderID, UserID: in.UserID})
	if err != nil {
		return nil, err
	}
	return &accountInfoOutput{Body: res}, nil
}
