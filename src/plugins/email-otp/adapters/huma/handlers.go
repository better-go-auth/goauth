package humaemailotp

import (
	"context"
	"net/http"
	"strings"

	humaadapter "github.com/better-go-auth/goauth/src/app/adapters/huma"
	authint "github.com/better-go-auth/goauth/src/app/services/interfaces"
	"github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/config"
	modeldtos "github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins/email-otp/dtos"
	"github.com/better-go-auth/goauth/src/plugins/email-otp/services"
	"github.com/better-go-auth/goauth/src/providers/authenticator"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	"github.com/danielgtaylor/huma/v2"
)

type EmailOTPHandler struct {
	Service *services.EmailOTPService
	Cookies *cookies.Manager
	Config  config.AuthConfig
}

func NewEmailOTPHandler(svc *services.EmailOTPService, cm *cookies.Manager, cfg config.AuthConfig) *EmailOTPHandler {
	return &EmailOTPHandler{
		Service: svc,
		Cookies: cm,
		Config:  cfg,
	}
}

func (h *EmailOTPHandler) meta(ctx context.Context) authint.SessionMeta {
	req := config.GetHTTPRequest(ctx)
	if req == nil {
		return authint.SessionMeta{}
	}
	ip := req.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = req.RemoteAddr
	}
	return authint.SessionMeta{
		IPAddress: ip,
		UserAgent: req.Header.Get("User-Agent"),
	}
}

// ─── SendVerificationOTP ───────────────────────────────────────────────────────

type sendVerificationOTPInput struct {
	Body dtos.SendVerificationOTPInput
}

type sendVerificationOTPOutput struct {
	Body dtos.SuccessResponse
}

func (h *EmailOTPHandler) SendVerificationOTP(ctx context.Context, in *sendVerificationOTPInput) (*sendVerificationOTPOutput, error) {
	req := config.GetHTTPRequest(ctx)
	if err := h.Service.SendVerificationOTP(ctx, in.Body.Email, in.Body.Type, req); err != nil {
		return nil, err
	}
	out := &sendVerificationOTPOutput{}
	out.Body.Success = true
	return out, nil
}

// ─── CheckVerificationOTP ──────────────────────────────────────────────────────

type checkVerificationOTPInput struct {
	Body dtos.CheckVerificationOTPInput
}

type checkVerificationOTPOutput struct {
	Body dtos.SuccessResponse
}

func (h *EmailOTPHandler) CheckVerificationOTP(ctx context.Context, in *checkVerificationOTPInput) (*checkVerificationOTPOutput, error) {
	if err := h.Service.CheckVerificationOTP(ctx, in.Body.Email, in.Body.OTP, in.Body.Type); err != nil {
		return nil, err
	}
	out := &checkVerificationOTPOutput{}
	out.Body.Success = true
	return out, nil
}

// ─── VerifyEmail ───────────────────────────────────────────────────────────────

type verifyEmailInput struct {
	Body dtos.VerifyEmailOTPInput
}

type verifyEmailOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      dtos.VerifyEmailResponse
}

func (h *EmailOTPHandler) VerifyEmail(ctx context.Context, in *verifyEmailInput) (*verifyEmailOutput, error) {
	req := config.GetHTTPRequest(ctx)
	session, user, err := h.Service.VerifyEmail(ctx, in.Body.Email, in.Body.OTP, h.meta(ctx), req)
	if err != nil {
		return nil, err
	}

	out := &verifyEmailOutput{}
	out.Body.Status = true
	if user != nil {
		userDto := modeldtos.UserFromModel(user)
		out.Body.User = &userDto
	}
	if session != nil && h.Cookies != nil {
		out.SetCookie = h.Cookies.SessionCookies(session.Session.Token, false)
	}
	return out, nil
}

// ─── SignIn ────────────────────────────────────────────────────────────────────

type signInInput struct {
	Body dtos.SignInEmailOTPInput
}

type signInOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      dtos.SignInResponse
}

func (h *EmailOTPHandler) SignIn(ctx context.Context, in *signInInput) (*signInOutput, error) {
	sw, err := h.Service.SignIn(ctx, in.Body.Email, in.Body.OTP, h.meta(ctx))
	if err != nil {
		return nil, err
	}

	out := &signInOutput{}
	if h.Cookies != nil {
		out.SetCookie = h.Cookies.SessionCookies(sw.Session.Token, false)
	}
	out.Body.Token = sw.Session.Token
	out.Body.User = &sw.User
	return out, nil
}

// ─── ResetPassword ─────────────────────────────────────────────────────────────

type resetPasswordInput struct {
	Body dtos.ResetPasswordOTPInput
}

type resetPasswordOutput struct {
	Body dtos.StatusResponse
}

func (h *EmailOTPHandler) ResetPassword(ctx context.Context, in *resetPasswordInput) (*resetPasswordOutput, error) {
	if err := h.Service.ResetPassword(ctx, in.Body.Email, in.Body.OTP, in.Body.Password); err != nil {
		return nil, err
	}
	out := &resetPasswordOutput{}
	out.Body.Status = true
	return out, nil
}

// ─── Email Change ─────────────────────────────────────────────────────────────

func (h *EmailOTPHandler) getSession(ctx context.Context, auth types.AuthHeaders) (*modeldtos.SessionWithUser, bool) {
	if sw, ok := humaadapter.FromContext(ctx); ok && sw != nil {
		return sw, true
	}
	if sw, ok := authenticator.SessionFromContext(ctx); ok && sw != nil {
		return sw, true
	}

	var tok string
	if auth.Authorization != "" {
		tok = strings.TrimPrefix(auth.Authorization, "Bearer ")
		tok = strings.TrimPrefix(tok, "bearer ")
	}
	if tok == "" && auth.Cookie != "" && h.Cookies != nil {
		tok, _ = h.Cookies.SessionToken(auth.Cookie)
	}
	if tok == "" {
		req := config.GetHTTPRequest(ctx)
		if req != nil {
			if a := req.Header.Get("Authorization"); a != "" {
				tok = strings.TrimPrefix(a, "Bearer ")
				tok = strings.TrimPrefix(tok, "bearer ")
			}
			if tok == "" && h.Cookies != nil {
				tok, _ = h.Cookies.SessionToken(req.Header.Get("Cookie"))
			}
		}
	}
	if tok != "" && h.Service != nil && h.Service.SessionManager() != nil {
		if sw, err := h.Service.SessionManager().Get(ctx, tok); err == nil && sw != nil {
			return sw, true
		}
	}

	return nil, false
}

type requestEmailChangeInput struct {
	types.AuthHeaders
	Body dtos.RequestEmailChangeInput
}

type requestEmailChangeOutput struct {
	Body dtos.StatusResponse
}

func (h *EmailOTPHandler) RequestEmailChange(ctx context.Context, in *requestEmailChangeInput) (*requestEmailChangeOutput, error) {
	sw, ok := h.getSession(ctx, in.AuthHeaders)
	if !ok || sw == nil {
		return nil, huma.NewError(http.StatusUnauthorized, "Unauthorized")
	}
	req := config.GetHTTPRequest(ctx)
	if err := h.Service.RequestEmailChange(ctx, sw.User.ID, in.Body.NewEmail, in.Body.OTP, req); err != nil {
		return nil, err
	}
	out := &requestEmailChangeOutput{}
	out.Body.Status = true
	return out, nil
}

type changeEmailInput struct {
	types.AuthHeaders
	Body dtos.ChangeEmailOTPInput
}

type changeEmailOutput struct {
	Body dtos.StatusResponse
}

func (h *EmailOTPHandler) ChangeEmail(ctx context.Context, in *changeEmailInput) (*changeEmailOutput, error) {
	sw, ok := h.getSession(ctx, in.AuthHeaders)
	if !ok || sw == nil {
		return nil, huma.NewError(http.StatusUnauthorized, "Unauthorized")
	}
	if _, err := h.Service.ChangeEmail(ctx, sw.User.ID, in.Body.NewEmail, in.Body.OTP); err != nil {
		return nil, err
	}
	out := &changeEmailOutput{}
	out.Body.Status = true
	return out, nil
}

