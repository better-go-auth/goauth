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

// GenerateOTPData carries parameters passed to a custom OTP generator callback.
type GenerateOTPData struct {
	Email string  `json:"email"`
	Type  OTPType `json:"type"`
}

// GenerateOTPFunc allows callers to provide a custom OTP code generator.
// Returning an empty string falls back to the default numeric generator.
type GenerateOTPFunc func(data GenerateOTPData, req *http.Request) (string, error)

// StoreOTPMode defines how the OTP code is stored in the verification table.
type StoreOTPMode string

const (
	StoreOTPPlain     StoreOTPMode = "plain"
	StoreOTPHashed    StoreOTPMode = "hashed"
	StoreOTPEncrypted StoreOTPMode = "encrypted"
)

// StoreOTPConfig mirrors Better Auth's `storeOTP` option.
// Supports "plain" (default), "hashed", "encrypted", or custom Hash / Encrypt+Decrypt callbacks.
type StoreOTPConfig struct {
	Mode    StoreOTPMode
	Hash    func(otp string) (string, error)
	Encrypt func(otp string) (string, error)
	Decrypt func(encrypted string) (string, error)
}

// ResendStrategy defines how requesting a new OTP behaves when an unexpired OTP already exists.
type ResendStrategy string

const (
	// ResendStrategyRotate always generates a new OTP code (default).
	ResendStrategyRotate ResendStrategy = "rotate"
	// ResendStrategyReuse resends the same OTP and extends its expiry when recoverable.
	// Falls back to "rotate" when OTP is hashed.
	ResendStrategyReuse ResendStrategy = "reuse"
)

// EmailOTPRateLimitConfig mirrors Better Auth's `rateLimit` option on Email OTP endpoints.
type EmailOTPRateLimitConfig struct {
	// Enabled controls whether per-endpoint rate limiting is enforced.
	// When nil, rate limiting is enabled automatically if Window > 0, Max > 0, or root RateLimit.Enabled is true.
	Enabled *bool
	// Window specifies the rate limit window duration (default: 60s).
	Window time.Duration
	// Max specifies the maximum requests allowed per window (default: 3).
	Max int
}

// EmailOTPChangeEmailConfig holds configuration options for email change operations.
type EmailOTPChangeEmailConfig struct {
	// Enabled controls whether email change via OTP is allowed (default false in Better Auth).
	Enabled bool

	// VerifyCurrentEmail requires an OTP sent to the user's current email before changing.
	VerifyCurrentEmail bool
}

// EmailOTPConfig holds configuration options for the Email OTP plugin.
type EmailOTPConfig struct {
	// SendVerificationOTP is the user-provided callback to send the OTP email.
	SendVerificationOTP SendVerificationOTP

	// OtpLength specifies the number of digits in the generated OTP. Default is 6.
	OtpLength int

	// ExpiresIn specifies how long the OTP code is valid for. Default is 5 minutes (300 seconds).
	ExpiresIn time.Duration

	// GenerateOTP is an optional custom function to generate the OTP code.
	GenerateOTP GenerateOTPFunc

	// OverrideDefaultEmailVerification when true bypasses link-based email verification in favor of OTP codes.
	OverrideDefaultEmailVerification bool

	// SendVerificationOnSignUp automatically sends an OTP code when a user completes registration.
	SendVerificationOnSignUp bool

	// DisableSignUp disables auto-creating accounts when signing in with OTP if the account doesn't exist.
	DisableSignUp bool

	// AllowedAttempts specifies the maximum verification attempts before the OTP is invalidated. Default is 3.
	AllowedAttempts int

	// StoreOTP configures how OTP values are stored in the database ("plain", "hashed", "encrypted", or custom hooks).
	StoreOTP StoreOTPConfig

	// ResendStrategy controls whether requesting a new OTP rotates or reuses an existing valid OTP. Default is "rotate".
	ResendStrategy ResendStrategy

	// ChangeEmail configures changing email via OTP.
	ChangeEmail EmailOTPChangeEmailConfig

	// RateLimit configures rate limiting for Email OTP endpoints (default: 3 requests per 60s window).
	RateLimit EmailOTPRateLimitConfig
}

// DefaultConfig returns the default configuration matching Better Auth specifications.
func DefaultConfig() EmailOTPConfig {
	return EmailOTPConfig{
		OtpLength:       6,
		ExpiresIn:       5 * time.Minute,
		AllowedAttempts: 3,
		StoreOTP: StoreOTPConfig{
			Mode: StoreOTPPlain,
		},
		ResendStrategy: ResendStrategyRotate,
		ChangeEmail: EmailOTPChangeEmailConfig{
			Enabled:            false,
			VerifyCurrentEmail: false,
		},
		RateLimit: EmailOTPRateLimitConfig{
			Window: 60 * time.Second,
			Max:    3,
		},
	}
}
