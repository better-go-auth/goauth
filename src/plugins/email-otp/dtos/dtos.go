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

type SuccessResponse = dtos.SuccessResponse
type StatusResponse = dtos.StatusResponse
type VerifyEmailResponse = dtos.VerifyEmailResponse
type SignInResponse = dtos.SignInResponse
