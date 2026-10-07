package humaadapter

import (
	"context"
	"net/http"
	"strings"

	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/models/dtos"
)

type signUpInput struct {
	Body struct {
		dtos.SignUpEmailInput
		_ struct{} `json:"-" additionalProperties:"true"`
	}
}

type signUpOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      struct {
		Token *string             `json:"token"`
		User  dtos.BetterAuthUser `json:"user"`
	}
}

func (h *handler) signUpEmail(ctx context.Context, in *signUpInput) (*signUpOutput, error) {
	if err := h.checkCallbackURL(in.Body.CallbackURL); err != nil {
		return nil, err
	}
	res, err := h.Auth.SignUpEmail(ctx, in.Body.SignUpEmailInput, h.meta(ctx))
	if err != nil {
		return nil, err
	}
	out := &signUpOutput{}
	out.Body.Token, out.Body.User = res.Token, res.User
	if res.Session != nil {
		out.SetCookie = h.Cookies.SessionCookies(res.Session.Session.Token, res.DontRemember)
	}
	return out, nil
}

type signInInput struct {
	Body struct {
		dtos.SignInEmailInput
		_ struct{} `json:"-" additionalProperties:"true"`
	}
}

type signInOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Location  string        `header:"Location"`
	Body      struct {
		Redirect bool                `json:"redirect"`
		Token    string              `json:"token"`
		URL      *string             `json:"url,omitempty"`
		User     dtos.BetterAuthUser `json:"user"`
	}
}

func (h *handler) signInEmail(ctx context.Context, in *signInInput) (*signInOutput, error) {
	if err := h.checkCallbackURL(in.Body.CallbackURL); err != nil {
		return nil, err
	}
	res, err := h.Auth.SignInEmail(ctx, in.Body.SignInEmailInput, h.meta(ctx))
	if err != nil {
		return nil, err
	}
	out := &signInOutput{SetCookie: h.Cookies.SessionCookies(res.Token, res.DontRemember)}
	if res.Redirect {
		// better-auth answers 200 with a Location header; the client follows `url`
		out.Location = *res.URL
	}
	out.Body.Redirect, out.Body.Token, out.Body.URL, out.Body.User = res.Redirect, res.Token, res.URL, res.User
	return out, nil
}

type signOutInput struct {
	Cookie string `header:"Cookie"`
}

type signOutOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      struct {
		Success bool `json:"success"`
	}
}

func (h *handler) signOut(ctx context.Context, in *signOutInput) (*signOutOutput, error) {
	if tok, ok := h.Cookies.SessionToken(in.Cookie); ok {
		// like better-auth, a failed delete still clears the cookies
		_ = h.Auth.SignOut(ctx, tok)
	}
	out := &signOutOutput{SetCookie: h.Cookies.ExpireSessionCookies()}
	out.Body.Success = true
	return out, nil
}

type verifyPasswordInput struct {
	Body dtos.VerifyPasswordInput
}

func (h *handler) verifyPassword(ctx context.Context, in *verifyPasswordInput) (*statusOutput, error) {
	if err := h.Auth.VerifyPassword(ctx, current(ctx), in.Body.Password); err != nil {
		return nil, err
	}
	return statusOK(), nil
}

type sendVerificationEmailInput struct {
	Body dtos.SendVerificationEmailInput
}

func (h *handler) sendVerificationEmail(ctx context.Context, in *sendVerificationEmailInput) (*statusOutput, error) {
	if err := h.checkURL(in.Body.CallbackURL, autherr.ErrInvalidCallbackURL); err != nil {
		return nil, err
	}
	if err := h.Auth.SendVerificationEmail(ctx, current(ctx), in.Body); err != nil {
		return nil, err
	}
	return statusOK(), nil
}

type verifyEmailInput struct {
	Token       string `query:"token" required:"true"`
	CallbackURL string `query:"callbackURL"`
}

type verifyEmailOutput struct {
	Status    int
	Location  string        `header:"Location"`
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      *verifyEmailBody
}

type verifyEmailBody struct {
	Status bool                 `json:"status"`
	User   *dtos.BetterAuthUser `json:"user"`
}

// verifyEmail mirrors GET /verify-email: with a callbackURL every outcome is a redirect
// (errors as ?error=CODE), otherwise JSON.
func (h *handler) verifyEmail(ctx context.Context, in *verifyEmailInput) (*verifyEmailOutput, error) {
	if err := h.checkURL(in.CallbackURL, autherr.ErrInvalidCallbackURL); err != nil {
		return nil, err
	}
	res, err := h.Auth.VerifyEmail(ctx, current(ctx), in.Token, in.CallbackURL, h.meta(ctx))
	if err != nil {
		if in.CallbackURL == "" {
			return nil, err
		}
		sep := "?"
		if strings.Contains(in.CallbackURL, "?") {
			sep = "&"
		}
		return &verifyEmailOutput{Status: http.StatusFound, Location: in.CallbackURL + sep + "error=" + errorCode(err)}, nil
	}
	out := &verifyEmailOutput{Status: http.StatusOK, SetCookie: h.sessionCookies(ctx, res.Session)}
	if in.CallbackURL != "" {
		out.Status, out.Location = http.StatusFound, in.CallbackURL
		return out, nil
	}
	out.Body = &verifyEmailBody{Status: res.Status, User: res.User}
	return out, nil
}

type changeEmailInput struct {
	Body dtos.ChangeEmailInput
}

func (h *handler) changeEmail(ctx context.Context, in *changeEmailInput) (*statusOutput, error) {
	if err := h.checkCallbackURL(in.Body.CallbackURL); err != nil {
		return nil, err
	}
	sw, err := h.Auth.ChangeEmail(ctx, current(ctx), in.Body)
	if err != nil {
		return nil, err
	}
	out := statusOK()
	out.SetCookie = h.sessionCookies(ctx, sw)
	return out, nil
}
