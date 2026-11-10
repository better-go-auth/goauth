package humaemailotp

import (
	"context"
	"net"
	"net/http"
	"strings"

	humaadapter "github.com/better-go-auth/goauth/src/app/adapters/huma"
	authint "github.com/better-go-auth/goauth/src/app/services/interfaces"
	"github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/config"
	modeldtos "github.com/better-go-auth/goauth/src/models/dtos"
	emailotpconfig "github.com/better-go-auth/goauth/src/plugins/email-otp/config"
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
	authFn  authenticator.AuthenticateFunc
}

func NewEmailOTPHandler(svc *services.EmailOTPService, cm *cookies.Manager, cfg config.AuthConfig, authFn ...authenticator.AuthenticateFunc) *EmailOTPHandler {
	var af authenticator.AuthenticateFunc
	if len(authFn) > 0 {
		af = authFn[0]
	}
	return &EmailOTPHandler{
		Service: svc,
		Cookies: cm,
		Config:  cfg,
		authFn:  af,
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

func (h *EmailOTPHandler) clientIP(ctx context.Context) string {
	req := config.GetHTTPRequest(ctx)
	if req == nil {
		return "global"
	}
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[0]); ip != "" {
			return ip
		}
	}
	if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil && host != "" {
		return host
	}
	if req.RemoteAddr != "" {
		return req.RemoteAddr
	}
	return "global"
}

func (h *EmailOTPHandler) checkRateLimit(ctx context.Context, path string) error {
	if h.Service == nil {
		return nil
	}
	return h.Service.CheckRateLimit(ctx, path, h.clientIP(ctx))
}

// ─── SendVerificationOTP ───────────────────────────────────────────────────────

type sendVerificationOTPInput struct {
	Body dtos.SendVerificationOTPInput
}

type sendVerificationOTPOutput struct {
	Body dtos.SuccessResponse
}

func (h *EmailOTPHandler) SendVerificationOTP(ctx context.Context, in *sendVerificationOTPInput) (*sendVerificationOTPOutput, error) {
	// Step 1: Enforce per-endpoint rate limit if configured
	if err := h.checkRateLimit(ctx, "/email-otp/send-verification-otp"); err != nil {
		return nil, err
	}
	// Step 2: Generate and dispatch OTP via service
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
	// Step 1: Enforce per-endpoint rate limit if configured
	if err := h.checkRateLimit(ctx, "/email-otp/check-verification-otp"); err != nil {
		return nil, err
	}
	// Step 2: Verify OTP without consuming it
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
	// Step 1: Enforce per-endpoint rate limit if configured
	if err := h.checkRateLimit(ctx, "/email-otp/verify-email"); err != nil {
		return nil, err
	}
	// Step 2: Verify email OTP and optionally issue session
	req := config.GetHTTPRequest(ctx)
	session, user, err := h.Service.VerifyEmail(ctx, in.Body.Email, in.Body.OTP, h.meta(ctx), req)
	if err != nil {
		return nil, err
	}

	// Step 3: Build Better Auth compatible response with optional session token & cookie
	out := &verifyEmailOutput{}
	out.Body.Status = true
	if user != nil {
		userDto := modeldtos.UserFromModel(user)
		out.Body.User = &userDto
	}
	if session != nil {
		tok := session.Session.Token
		out.Body.Token = &tok
		if h.Cookies != nil {
			out.SetCookie = h.Cookies.SessionCookies(tok, false)
		}
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
	// Step 1: Enforce per-endpoint rate limit if configured
	if err := h.checkRateLimit(ctx, "/sign-in/email-otp"); err != nil {
		return nil, err
	}
	// Step 2: Authenticate or auto-register user with OTP
	sw, err := h.Service.SignInWithProfile(ctx, in.Body.Email, in.Body.OTP, in.Body.Name, in.Body.Image, h.meta(ctx))
	if err != nil {
		return nil, err
	}

	// Step 3: Attach session cookie and return session token + user
	out := &signInOutput{}
	if h.Cookies != nil {
		out.SetCookie = h.Cookies.SessionCookies(sw.Session.Token, false)
	}
	out.Body.Token = sw.Session.Token
	out.Body.User = &sw.User
	return out, nil
}

// ─── RequestPasswordReset ─────────────────────────────────────────────────────

type requestPasswordResetInput struct {
	Body dtos.RequestPasswordResetOTPInput
}

type requestPasswordResetOutput struct {
	Body dtos.SuccessResponse
}

func (h *EmailOTPHandler) RequestPasswordReset(ctx context.Context, in *requestPasswordResetInput) (*requestPasswordResetOutput, error) {
	// Step 1: Enforce per-endpoint rate limit if configured
	if err := h.checkRateLimit(ctx, "/email-otp/request-password-reset"); err != nil {
		return nil, err
	}
	// Step 2: Dispatch forget-password OTP
	req := config.GetHTTPRequest(ctx)
	if err := h.Service.SendVerificationOTP(ctx, in.Body.Email, emailotpconfig.OTPTypeForgetPassword, req); err != nil {
		return nil, err
	}
	out := &requestPasswordResetOutput{}
	out.Body.Success = true
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
	// Step 1: Enforce per-endpoint rate limit if configured
	if err := h.checkRateLimit(ctx, "/email-otp/reset-password"); err != nil {
		return nil, err
	}
	// Step 2: Validate OTP and reset password
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
	if h.authFn != nil {
		if sw, err := h.authFn(ctx, auth); err == nil && sw != nil {
			return sw, true
		}
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
	// Step 1: Enforce per-endpoint rate limit if configured
	if err := h.checkRateLimit(ctx, "/email-otp/request-email-change"); err != nil {
		return nil, err
	}
	// Step 2: Require authenticated session
	sw, ok := h.getSession(ctx, in.AuthHeaders)
	if !ok || sw == nil {
		return nil, huma.NewError(http.StatusUnauthorized, "Unauthorized")
	}
	// Step 3: Dispatch email change OTP
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
	// Step 1: Enforce per-endpoint rate limit if configured
	if err := h.checkRateLimit(ctx, "/email-otp/change-email"); err != nil {
		return nil, err
	}
	// Step 2: Require authenticated session
	sw, ok := h.getSession(ctx, in.AuthHeaders)
	if !ok || sw == nil {
		return nil, huma.NewError(http.StatusUnauthorized, "Unauthorized")
	}
	// Step 3: Verify OTP and update user's email
	if _, err := h.Service.ChangeEmail(ctx, sw.User.ID, in.Body.NewEmail, in.Body.OTP); err != nil {
		return nil, err
	}
	out := &changeEmailOutput{}
	out.Body.Status = true
	return out, nil
}
