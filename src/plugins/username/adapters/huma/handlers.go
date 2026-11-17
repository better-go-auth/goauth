// Package humausername mounts the username plugin endpoints on a Huma API.
package humausername

import (
	"context"
	"net/http"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/plugins/username/dtos"
	"github.com/better-go-auth/goauth/src/plugins/username/services"
)

// SignInPath is the sign-in endpoint path reported to AfterSignIn interceptors (two-factor).
const SignInPath = "/sign-in/username"

// Handler adapts the username Service to Huma operations.
type Handler struct {
	Service *services.Service
}

// NewHandler builds the Huma handler.
func NewHandler(svc *services.Service) *Handler { return &Handler{Service: svc} }

// ─── POST /sign-in/username ──────────────────────────────────────────────────

type signInInput struct {
	Body struct {
		dtos.SignInUsernameInput
		_ struct{} `json:"-" additionalProperties:"true"`
	}
}

type signInOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Location  string        `header:"Location"`
	// Body is {redirect, token, url, user}, or a plugin challenge (two-factor's {"twoFactorRedirect": true}).
	Body any
}

// SignIn signs a user in with username and password.
func (h *Handler) SignIn(ctx context.Context, in *signInInput) (*signInOutput, error) {
	kit := h.Service.Kit()
	// Step 1: reject untrusted callback URLs before doing any work
	if in.Body.CallbackURL != nil {
		if err := kit.CheckURL(*in.Body.CallbackURL, autherr.ErrInvalidCallbackURL); err != nil {
			return nil, err
		}
	}
	// Step 2: check the credentials and create the session
	res, err := h.Service.SignIn(ctx, services.SignInInput{
		Username: in.Body.Username, Password: in.Body.Password, RememberMe: in.Body.RememberMe, CallbackURL: in.Body.CallbackURL,
	})
	if err != nil {
		return nil, err
	}
	// Step 3: let plugins (two-factor) replace the response before any session cookie is written
	ch, err := kit.SignInChallenge(ctx, SignInPath, res.Session, res.DontRemember)
	if err != nil {
		return nil, err
	}
	if ch.Replaces() {
		return &signInOutput{SetCookie: ch.Cookies, Body: ch.Body}, nil
	}
	// Step 4: session cookies (plus extra interceptor cookies) and better-auth's {redirect, token, url, user}
	out := &signInOutput{
		SetCookie: append(kit.SessionCookies(res.Session, res.DontRemember), ch.Extra()...),
		Body: dtos.SignInUsernameResponse{
			Redirect: res.Redirect, Token: res.Session.Session.Token, URL: res.URL, User: res.Session.User,
		},
	}
	if res.Redirect {
		out.Location = *res.URL
	}
	return out, nil
}

// ─── POST /is-username-available ─────────────────────────────────────────────

type isUsernameAvailableInput struct {
	Body struct {
		dtos.IsUsernameAvailableInput
		_ struct{} `json:"-" additionalProperties:"true"`
	}
}

type isUsernameAvailableOutput struct {
	Body dtos.IsUsernameAvailableResponse
}

// IsUsernameAvailable reports whether a username is free.
func (h *Handler) IsUsernameAvailable(ctx context.Context, in *isUsernameAvailableInput) (*isUsernameAvailableOutput, error) {
	ok, err := h.Service.IsUsernameAvailable(ctx, in.Body.Username)
	if err != nil {
		return nil, err
	}
	return &isUsernameAvailableOutput{Body: dtos.IsUsernameAvailableResponse{Available: ok}}, nil
}
