package humaadapter

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/models/dtos"
)

type signUpInput struct {
	// RawBody keeps the full JSON body so plugins can read their own fields (UserInput hooks).
	RawBody []byte
	Body    struct {
		dtos.SignUpEmailInput
		_ struct{} `json:"-" additionalProperties:"true"`
	}
}

type signUpOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      struct {
		Token *string           `json:"token"`
		User  dtos.UserResponse `json:"user"`
	}
}

func (h *handler) SignUpEmail(ctx context.Context, in *signUpInput) (*signUpOutput, error) {
	if err := h.checkCallbackURL(ctx, in.Body.CallbackURL); err != nil {
		return nil, err
	}
	// pass the extra body fields (e.g. the username plugin's username) to the service
	body := in.Body.SignUpEmailInput
	if len(in.RawBody) > 0 {
		extra := map[string]any{}
		if json.Unmarshal(in.RawBody, &extra) == nil {
			body.AdditionalFields = extra
		}
	}
	res, err := h.Auth.SignUpEmail(ctx, body, h.meta(ctx))
	if err != nil {
		return nil, err
	}
	out := &signUpOutput{}
	out.Body.Token, out.Body.User = res.Token, res.User
	if res.Session != nil {
		out.SetCookie = h.Cookies.SessionCookiesWithData(res.Session, res.DontRemember)
	}
	return out, nil
}

type signInInput struct {
	Body struct {
		dtos.SignInEmailInput
		_ struct{} `json:"-" additionalProperties:"true"`
	}
}

// signInBody is better-auth's POST /sign-in/email response.
type signInBody struct {
	Redirect bool              `json:"redirect"`
	Token    string            `json:"token"`
	URL      *string           `json:"url,omitempty"`
	User     dtos.UserResponse `json:"user"`
}

type signInOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Location  string        `header:"Location"`
	// Body is a signInBody, or a plugin challenge (e.g. two-factor's {"twoFactorRedirect": true}).
	Body any
}

func (h *handler) SignInEmail(ctx context.Context, in *signInInput) (*signInOutput, error) {
	// Step 1: reject untrusted callback URLs before doing any work
	if err := h.checkCallbackURL(ctx, in.Body.CallbackURL); err != nil {
		return nil, err
	}
	// Step 2: verify the credentials and create the session
	res, err := h.Auth.SignInEmail(ctx, in.Body.SignInEmailInput, h.meta(ctx))
	if err != nil {
		return nil, err
	}
	// Step 3: plugins may still replace the response (two-factor challenge): goauth's endpoint-hook
	// middleware runs the OnAfterSignIn interceptors on it before it is sent
	// Step 4: write the session cookies and better-auth's {redirect, token, url, user}
	out := &signInOutput{SetCookie: h.Cookies.SessionCookiesWithData(res.Session, res.DontRemember)}
	if res.Redirect {
		// better-auth answers 200 with a Location header; the client follows `url`
		out.Location = *res.URL
	}
	out.Body = signInBody{Redirect: res.Redirect, Token: res.Token, URL: res.URL, User: res.User}
	return out, nil
}

type signOutInput struct {
	Cookie        string `header:"Cookie"`
	Authorization string `header:"Authorization"`
}

type signOutOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      struct {
		Success bool `json:"success"`
	}
}

func (h *handler) SignOut(ctx context.Context, in *signOutInput) (*signOutOutput, error) {
	tok, ok := h.Cookies.SessionToken(in.Cookie)
	if !ok {
		if btok, bok := FromBearerContext(ctx); bok {
			tok, ok = btok, true
		}
	}
	if ok {
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

func (h *handler) VerifyPassword(ctx context.Context, in *verifyPasswordInput) (*statusOutput, error) {
	if err := h.Auth.VerifyPassword(ctx, current(ctx), in.Body.Password); err != nil {
		return nil, err
	}
	return statusOK(), nil
}

type sendVerificationEmailInput struct {
	Body dtos.SendVerificationEmailInput
}

func (h *handler) SendVerificationEmail(ctx context.Context, in *sendVerificationEmailInput) (*statusOutput, error) {
	if err := h.checkURL(ctx, in.Body.CallbackURL, autherr.ErrInvalidCallbackURL); err != nil {
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
	Status bool               `json:"status"`
	User   *dtos.UserResponse `json:"user"`
}

// VerifyEmail mirrors GET /verify-email: with a callbackURL every outcome is a redirect
// (errors as ?error=CODE), otherwise JSON.
func (h *handler) VerifyEmail(ctx context.Context, in *verifyEmailInput) (*verifyEmailOutput, error) {
	if err := h.checkURL(ctx, in.CallbackURL, autherr.ErrInvalidCallbackURL); err != nil {
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

func (h *handler) ChangeEmail(ctx context.Context, in *changeEmailInput) (*statusOutput, error) {
	if err := h.checkCallbackURL(ctx, in.Body.CallbackURL); err != nil {
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
