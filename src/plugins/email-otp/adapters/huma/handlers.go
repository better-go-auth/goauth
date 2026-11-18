package humaemailotp

import (
	"context"
	"net/http"
	"strings"

	humaadapter "github.com/better-go-auth/goauth/src/app/adapters/huma"
	authint "github.com/better-go-auth/goauth/src/app/services/interfaces"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/config"
	modeldtos "github.com/better-go-auth/goauth/src/models/dtos"
	emailotpconfig "github.com/better-go-auth/goauth/src/plugins/email-otp/config"
	"github.com/better-go-auth/goauth/src/plugins/email-otp/dtos"
	"github.com/better-go-auth/goauth/src/plugins/email-otp/services"
	"github.com/better-go-auth/goauth/src/providers/authenticator"
	"github.com/better-go-auth/goauth/src/providers/cookies"
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

// meta returns the session IP / user agent, resolved like core sign-in (Advanced.IPAddress headers, a
// parsed IP instead of the raw X-Forwarded-For list).
func (h *EmailOTPHandler) meta(ctx context.Context) authint.SessionMeta {
	return humaadapter.SessionMeta(h.Config, ctx)
}

// ─── SendVerificationOTP ───────────────────────────────────────────────────────

type sendVerificationOTPInput struct {
	Body dtos.SendVerificationOTPInput
}

type sendVerificationOTPOutput struct {
	Body dtos.SuccessResponse
}

func (h *EmailOTPHandler) SendVerificationOTP(ctx context.Context, in *sendVerificationOTPInput) (*sendVerificationOTPOutput, error) {
	// Step 1: rate limiting (/email-otp/send-verification-otp) is done by goauth's global limiter, see Plugin.RateLimitRules
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
	// Step 1: rate limiting (/email-otp/check-verification-otp) is done by goauth's global limiter, see Plugin.RateLimitRules
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
	// Step 1: rate limiting (/email-otp/verify-email) is done by goauth's global limiter, see Plugin.RateLimitRules
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
			out.SetCookie = h.Cookies.SessionCookiesWithData(session, false)
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
	// Step 1: rate limiting (/sign-in/email-otp) is done by goauth's global limiter, see Plugin.RateLimitRules
	// Step 2: Authenticate or auto-register user with OTP
	sw, err := h.Service.SignInWithProfile(ctx, in.Body.Email, in.Body.OTP, in.Body.Name, in.Body.Image, h.meta(ctx))
	if err != nil {
		return nil, err
	}

	// Step 3: Attach session cookie and return session token + user
	out := &signInOutput{}
	if h.Cookies != nil {
		// include session_data when the cookie cache is enabled, like core sign-in
		out.SetCookie = h.Cookies.SessionCookiesWithData(sw, false)
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
	// Step 1: rate limiting (/email-otp/request-password-reset) is done by goauth's global limiter, see Plugin.RateLimitRules
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
	// Step 1: rate limiting (/email-otp/reset-password) is done by goauth's global limiter, see Plugin.RateLimitRules
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

// sensitiveSession is better-auth's sensitiveSessionMiddleware (used by /email-otp/request-email-change and
// /email-otp/change-email): the session behind the signed session cookie or bearer token is loaded from the
// session store, ignoring the cookie cache and any session an earlier middleware attached from it, so a revoked
// session that is still cached cannot change the email. Without a session it answers 401 UNAUTHORIZED.
func (h *EmailOTPHandler) sensitiveSession(ctx context.Context, auth types.AuthHeaders) (*modeldtos.SessionWithUser, error) {
	// Step 1: the session token: the signed cookie, then the bearer token the bearer plugin verified
	cookieHeader := auth.Cookie
	if req := config.GetHTTPRequest(ctx); cookieHeader == "" && req != nil {
		cookieHeader = req.Header.Get("Cookie")
	}
	var tok string
	if h.Cookies != nil {
		tok, _ = h.Cookies.SessionToken(cookieHeader)
	}
	if tok == "" {
		tok, _ = humaadapter.FromBearerContext(ctx)
	}
	// Step 2: no session token: other goauth transports (access-token JWTs) authenticate the request
	if tok == "" {
		if sw, ok := h.getSession(ctx, auth); ok && sw != nil {
			return sw, nil
		}
		return nil, autherr.ErrUnauthorized
	}
	// Step 3: the session store (database / secondary storage), never the cookie cache
	if h.Service == nil || h.Service.SessionManager() == nil {
		return nil, autherr.ErrUnauthorized
	}
	sw, err := h.Service.SessionManager().Get(ctx, tok)
	if err != nil || sw == nil {
		return nil, autherr.ErrUnauthorized
	}
	return sw, nil
}

type requestEmailChangeInput struct {
	types.AuthHeaders
	Body dtos.RequestEmailChangeInput
}

// requestEmailChangeOutput is better-auth's {"success": true}.
type requestEmailChangeOutput struct {
	Body dtos.SuccessResponse
}

func (h *EmailOTPHandler) RequestEmailChange(ctx context.Context, in *requestEmailChangeInput) (*requestEmailChangeOutput, error) {
	// Step 1: rate limiting (/email-otp/request-email-change) is done by goauth's global limiter, see Plugin.RateLimitRules
	// Step 2: Require a session read from the session store, not the cookie cache (sensitiveSessionMiddleware)
	sw, err := h.sensitiveSession(ctx, in.AuthHeaders)
	if err != nil {
		return nil, err
	}
	// Step 3: Dispatch email change OTP
	req := config.GetHTTPRequest(ctx)
	if err := h.Service.RequestEmailChange(ctx, sw.User.ID, in.Body.NewEmail, in.Body.OTP, req); err != nil {
		return nil, err
	}
	out := &requestEmailChangeOutput{}
	out.Body.Success = true
	return out, nil
}

type changeEmailInput struct {
	types.AuthHeaders
	Body dtos.ChangeEmailOTPInput
}

// changeEmailOutput is better-auth's {"success": true}; the session cookie is rewritten with the new email.
type changeEmailOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      dtos.SuccessResponse
}

func (h *EmailOTPHandler) ChangeEmail(ctx context.Context, in *changeEmailInput) (*changeEmailOutput, error) {
	// Step 1: rate limiting (/email-otp/change-email) is done by goauth's global limiter, see Plugin.RateLimitRules
	// Step 2: Require a session read from the session store, not the cookie cache (sensitiveSessionMiddleware)
	sw, err := h.sensitiveSession(ctx, in.AuthHeaders)
	if err != nil {
		return nil, err
	}
	// Step 3: Verify OTP and update user's email
	updated, err := h.Service.ChangeEmail(ctx, sw.User.ID, in.Body.NewEmail, in.Body.OTP)
	if err != nil {
		return nil, err
	}
	out := &changeEmailOutput{}
	out.Body.Success = true
	// Step 4: rewrite the cached session_data cookie with the new email (better-auth setSessionCookie)
	if h.Cookies != nil && h.Cookies.CookieCacheEnabled() && updated != nil {
		next := *sw
		next.User = modeldtos.UserFromModel(updated)
		out.SetCookie = h.Cookies.SessionCookiesWithData(&next, h.Cookies.DontRemember(in.Cookie))
	}
	return out, nil
}
