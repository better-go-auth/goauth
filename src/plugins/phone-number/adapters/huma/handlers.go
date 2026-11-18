// Package humaphonenumber mounts the phone-number plugin endpoints on a Huma API.
package humaphonenumber

import (
	"context"
	"encoding/json"
	"net/http"

	modeldtos "github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins/phone-number/dtos"
	"github.com/better-go-auth/goauth/src/plugins/phone-number/services"
)

// SignInPath is the sign-in endpoint path reported to AfterSignIn interceptors (two-factor).
const SignInPath = "/sign-in/phone-number"

// Handler adapts PhoneNumberService to Huma operations.
type Handler struct {
	Service *services.PhoneNumberService
}

// NewHandler builds the Huma handler.
func NewHandler(svc *services.PhoneNumberService) *Handler { return &Handler{Service: svc} }

// ─── POST /sign-in/phone-number ──────────────────────────────────────────────

type signInInput struct {
	Body struct {
		dtos.SignInPhoneNumberInput
		_ struct{} `json:"-" additionalProperties:"true"`
	}
}

type signInOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	// Body is {token, user}, or a plugin challenge (two-factor's {"twoFactorRedirect": true}).
	Body any
}

// SignIn signs a user in with phone number and password.
func (h *Handler) SignIn(ctx context.Context, in *signInInput) (*signInOutput, error) {
	kit := h.Service.Kit()
	// Step 1: check the credentials and create the session
	res, err := h.Service.SignIn(ctx, in.Body.PhoneNumber, in.Body.Password, in.Body.RememberMe)
	if err != nil {
		return nil, err
	}
	// Step 2: plugins (two-factor) may still replace the response: goauth's endpoint-hook middleware runs
	// the OnAfterSignIn interceptors on SignInPath responses before they are sent
	// Step 3: session cookies and better-auth's {token, user}
	return &signInOutput{
		SetCookie: kit.SessionCookies(res.Session, res.DontRemember),
		Body:      dtos.SignInPhoneNumberResponse{Token: res.Session.Session.Token, User: res.Session.User},
	}, nil
}

// ─── POST /phone-number/send-otp ─────────────────────────────────────────────

type sendOTPInput struct {
	Body struct {
		dtos.SendOTPInput
		_ struct{} `json:"-" additionalProperties:"true"`
	}
}

type sendOTPOutput struct {
	Body dtos.MessageResponse
}

// SendOTP sends a verification code by SMS.
func (h *Handler) SendOTP(ctx context.Context, in *sendOTPInput) (*sendOTPOutput, error) {
	if err := h.Service.SendOTP(ctx, in.Body.PhoneNumber); err != nil {
		return nil, err
	}
	return &sendOTPOutput{Body: dtos.MessageResponse{Message: "code sent"}}, nil
}

// ─── POST /phone-number/verify ───────────────────────────────────────────────

type verifyInput struct {
	RawBody []byte
	Body    struct {
		dtos.VerifyInput
		_ struct{} `json:"-" additionalProperties:"true"`
	}
}

type verifyOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      dtos.VerifyResponse
}

// Verify checks a code and signs the user in, signs them up, or attaches the number to their account.
func (h *Handler) Verify(ctx context.Context, in *verifyInput) (*verifyOutput, error) {
	kit := h.Service.Kit()
	// Step 1: keep the extra body fields (better-auth's additional user fields on sign-up)
	extra := map[string]any{}
	if len(in.RawBody) > 0 {
		_ = json.Unmarshal(in.RawBody, &extra)
	}
	for _, k := range []string{"phoneNumber", "code", "disableSession", "updatePhoneNumber"} {
		delete(extra, k)
	}
	// Step 2: verify the code and run the requested branch
	res, err := h.Service.Verify(ctx, services.VerifyInput{
		PhoneNumber:       in.Body.PhoneNumber,
		Code:              in.Body.Code,
		DisableSession:    in.Body.DisableSession,
		UpdatePhoneNumber: in.Body.UpdatePhoneNumber,
		Extra:             extra,
	})
	if err != nil {
		return nil, err
	}
	// Step 3: build {status, token, user}
	out := &verifyOutput{}
	user := modeldtos.UserFromModel(res.User)
	out.Body = dtos.VerifyResponse{Status: true, Token: res.Token, User: &user}
	// Step 4: cookies for a new session, or the refreshed cookie cache of the current one
	switch {
	case res.Session != nil:
		out.SetCookie = kit.SessionCookies(res.Session, false)
	case res.Current != nil:
		dontRemember := false
		if req := kit.Request(ctx); req != nil {
			dontRemember = kit.Cookies.DontRemember(req.Header.Get("Cookie"))
		}
		out.SetCookie = kit.SessionCookies(res.Current, dontRemember)
	}
	return out, nil
}

// ─── POST /phone-number/request-password-reset ───────────────────────────────

type requestPasswordResetInput struct {
	Body struct {
		dtos.RequestPasswordResetInput
		_ struct{} `json:"-" additionalProperties:"true"`
	}
}

type statusOutput struct {
	Body dtos.StatusResponse
}

// RequestPasswordReset sends a password reset code (always answers {status: true}).
func (h *Handler) RequestPasswordReset(ctx context.Context, in *requestPasswordResetInput) (*statusOutput, error) {
	if err := h.Service.RequestPasswordReset(ctx, in.Body.PhoneNumber); err != nil {
		return nil, err
	}
	return &statusOutput{Body: dtos.StatusResponse{Status: true}}, nil
}

// ─── POST /phone-number/reset-password ───────────────────────────────────────

type resetPasswordInput struct {
	Body struct {
		dtos.ResetPasswordInput
		_ struct{} `json:"-" additionalProperties:"true"`
	}
}

// ResetPassword sets a new password with a reset code.
func (h *Handler) ResetPassword(ctx context.Context, in *resetPasswordInput) (*statusOutput, error) {
	if err := h.Service.ResetPassword(ctx, in.Body.PhoneNumber, in.Body.OTP, in.Body.NewPassword); err != nil {
		return nil, err
	}
	return &statusOutput{Body: dtos.StatusResponse{Status: true}}, nil
}
