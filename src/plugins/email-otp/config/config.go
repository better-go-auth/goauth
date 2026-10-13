package config

import (
	"net/http"
	"time"
)

// OTPType represents the purpose of the One-Time Password.
type OTPType string

const (
	OTPTypeSignIn            OTPType = "sign-in"
	OTPTypeEmailVerification OTPType = "email-verification"
	OTPTypeForgetPassword    OTPType = "forget-password"
	OTPTypeChangeEmail       OTPType = "change-email"
)

// SendVerificationOTPData carries parameters passed to the OTP sender callback.
type SendVerificationOTPData struct {
	Email string  `json:"email"`
	OTP   string  `json:"otp"`
	Type  OTPType `json:"type"`
}

// SendVerificationOTP is the callback function invoked to deliver the OTP code (e.g. via email).
type SendVerificationOTP func(data SendVerificationOTPData, req *http.Request) error

// EmailOTPChangeEmailConfig holds configuration options for email change operations.
type EmailOTPChangeEmailConfig struct {
	// Enabled controls whether email change via OTP is allowed (default true).
	Enabled bool

	// VerifyCurrentEmail requires an OTP sent to the user's current email before changing.
	VerifyCurrentEmail bool
}

// EmailOTPConfig holds configuration options for the Email OTP plugin.
type EmailOTPConfig struct {
	// OtpLength specifies the number of digits in the generated OTP. Default is 6.
	OtpLength int

	// ExpiresIn specifies how long the OTP code is valid for. Default is 5 minutes (300 seconds).
	ExpiresIn time.Duration

	// SendVerificationOTP is the user-provided callback to send the OTP email.
	SendVerificationOTP SendVerificationOTP

	// OverrideDefaultEmailVerification when true bypasses link-based email verification in favor of OTP codes.
	OverrideDefaultEmailVerification bool

	// SendVerificationOnSignUp automatically sends an OTP code when a user completes registration.
	SendVerificationOnSignUp bool

	// DisableSignUp disables auto-creating accounts when signing in with OTP if the account doesn't exist.
	DisableSignUp bool

	// ChangeEmail configures changing email via OTP.
	ChangeEmail EmailOTPChangeEmailConfig
}

// DefaultConfig returns the default configuration matching Better Auth specifications.
func DefaultConfig() EmailOTPConfig {
	return EmailOTPConfig{
		OtpLength: 6,
		ExpiresIn: 5 * time.Minute,
		ChangeEmail: EmailOTPChangeEmailConfig{
			Enabled: true,
		},
	}
}
