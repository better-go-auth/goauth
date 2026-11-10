package dtos

import (
	"github.com/better-go-auth/goauth/src/models/dtos"
	emailotpconfig "github.com/better-go-auth/goauth/src/plugins/email-otp/config"
)

type SendVerificationOTPInput struct {
	Email string                 `json:"email" doc:"User's email address"`
	Type  emailotpconfig.OTPType `json:"type" doc:"Purpose: sign-in, email-verification, or forget-password"`
}

type CheckVerificationOTPInput struct {
	Email string                 `json:"email" doc:"User's email address"`
	OTP   string                 `json:"otp" doc:"The verification code"`
	Type  emailotpconfig.OTPType `json:"type" doc:"Purpose: sign-in, email-verification, or forget-password"`
}

type VerifyEmailOTPInput struct {
	Email string `json:"email" doc:"User's email address"`
	OTP   string `json:"otp" doc:"The verification code"`
}

type SignInEmailOTPInput struct {
	Email string `json:"email" doc:"User's email address"`
	OTP   string `json:"otp" doc:"The verification code"`
	Name  string `json:"name,omitempty" doc:"Optional user display name on first sign-up"`
	Image string `json:"image,omitempty" doc:"Optional user profile image URL on first sign-up"`
}

type RequestPasswordResetOTPInput struct {
	Email string `json:"email" doc:"User's email address"`
}

type ResetPasswordOTPInput struct {
	Email    string `json:"email" doc:"User's email address"`
	OTP      string `json:"otp" doc:"The verification code"`
	Password string `json:"password" doc:"The new password"`
}

type RequestEmailChangeInput struct {
	NewEmail string  `json:"newEmail" doc:"The target new email address to change to"`
	OTP      *string `json:"otp,omitempty" doc:"OTP code sent to current email (if verifyCurrentEmail is required)"`
}

type ChangeEmailOTPInput struct {
	NewEmail string `json:"newEmail" doc:"The target new email address to change to"`
	OTP      string `json:"otp" doc:"The verification code received on the new email address"`
}

// VerifyEmailResponse matches Better Auth's /email-otp/verify-email response shape.
type VerifyEmailResponse struct {
	Status bool               `json:"status"`
	Token  *string            `json:"token"`
	User   *dtos.UserResponse `json:"user"`
}

type SuccessResponse = dtos.SuccessResponse
type StatusResponse = dtos.StatusResponse
type SignInResponse = dtos.SignInResponse
