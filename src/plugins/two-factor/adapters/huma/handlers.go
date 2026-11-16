// Package huma mounts the two-factor endpoints on a Huma API.
package huma

import (
	"context"
	"net/http"

	"github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	tfdtos "github.com/better-go-auth/goauth/src/plugins/two-factor/dtos"
	"github.com/better-go-auth/goauth/src/plugins/two-factor/services"
)

// Handler adapts the service to Huma operations.
type Handler struct {
	svc *services.Service
	kit *pluginkit.Kit
}

// NewHandler returns the HTTP handler of the two-factor endpoints.
func NewHandler(svc *services.Service, kit *pluginkit.Kit) *Handler {
	return &Handler{svc: svc, kit: kit}
}

// Output is a JSON body plus Set-Cookie headers.
type Output struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      any
}

func toOutput(res *services.Result, err error) (*Output, error) {
	if err != nil {
		return nil, err
	}
	return &Output{SetCookie: res.Cookies, Body: res.Body}, nil
}

type enableInput struct {
	Body tfdtos.EnableInput
}

type passwordInput struct {
	Body tfdtos.PasswordInput
}

type verifyCodeInput struct {
	Body tfdtos.VerifyCodeInput
}

type sendOTPInput struct {
	Body *tfdtos.SendOTPInput `required:"false"`
}

type verifyBackupCodeInput struct {
	Body tfdtos.VerifyBackupCodeInput
}

// Enable handles POST /two-factor/enable.
func (h *Handler) Enable(ctx context.Context, in *enableInput) (*Output, error) {
	// Step 1: session and body validation
	sw := h.kit.Current(ctx)
	if sw == nil {
		return nil, autherr.ErrUnauthorized
	}
	if err := services.RequirePasswordField(in.Body.Password, h.svc.Config().AllowPasswordless); err != nil {
		return nil, err
	}
	// Step 2: run the endpoint
	return toOutput(h.svc.Enable(ctx, sw, in.Body))
}

// Disable handles POST /two-factor/disable.
func (h *Handler) Disable(ctx context.Context, in *passwordInput) (*Output, error) {
	sw := h.kit.Current(ctx)
	if sw == nil {
		return nil, autherr.ErrUnauthorized
	}
	if err := services.RequirePasswordField(in.Body.Password, h.svc.Config().AllowPasswordless); err != nil {
		return nil, err
	}
	return toOutput(h.svc.Disable(ctx, sw, in.Body.Password))
}

// GetTOTPURI handles POST /two-factor/get-totp-uri.
func (h *Handler) GetTOTPURI(ctx context.Context, in *passwordInput) (*Output, error) {
	sw := h.kit.Current(ctx)
	if sw == nil {
		return nil, autherr.ErrUnauthorized
	}
	if err := services.RequirePasswordField(in.Body.Password, h.svc.Config().TOTPAllowPasswordless()); err != nil {
		return nil, err
	}
	return toOutput(h.svc.GetTOTPURI(ctx, sw, in.Body.Password))
}

// VerifyTOTP handles POST /two-factor/verify-totp.
func (h *Handler) VerifyTOTP(ctx context.Context, in *verifyCodeInput) (*Output, error) {
	return toOutput(h.svc.VerifyTOTP(ctx, in.Body))
}

// SendOTP handles POST /two-factor/send-otp.
func (h *Handler) SendOTP(ctx context.Context, _ *sendOTPInput) (*Output, error) {
	return toOutput(h.svc.SendOTP(ctx))
}

// VerifyOTP handles POST /two-factor/verify-otp.
func (h *Handler) VerifyOTP(ctx context.Context, in *verifyCodeInput) (*Output, error) {
	return toOutput(h.svc.VerifyOTP(ctx, in.Body))
}

// GenerateBackupCodes handles POST /two-factor/generate-backup-codes.
func (h *Handler) GenerateBackupCodes(ctx context.Context, in *passwordInput) (*Output, error) {
	sw := h.kit.Current(ctx)
	if sw == nil {
		return nil, autherr.ErrUnauthorized
	}
	if err := services.RequirePasswordField(in.Body.Password, h.svc.Config().BackupCodesAllowPasswordless()); err != nil {
		return nil, err
	}
	return toOutput(h.svc.GenerateBackupCodes(ctx, sw, in.Body.Password))
}

// VerifyBackupCode handles POST /two-factor/verify-backup-code.
func (h *Handler) VerifyBackupCode(ctx context.Context, in *verifyBackupCodeInput) (*Output, error) {
	return toOutput(h.svc.VerifyBackupCode(ctx, in.Body))
}
