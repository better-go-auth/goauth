// Package config holds the options of the phone-number plugin (better-auth's PhoneNumberOptions).
package config

import (
	"net/http"
	"time"

	"github.com/better-go-auth/goauth/src/models"
)

// Defaults mirror better-auth's phoneNumber() plugin.
const (
	DefaultOTPLength       = 6
	DefaultExpiresIn       = 300 * time.Second
	DefaultAllowedAttempts = 3
)

// OTPData is passed to SendOTP, SendPasswordResetOTP and VerifyOTP.
type OTPData struct {
	PhoneNumber string
	Code        string
}

// VerificationData is passed to CallbackOnVerification after a phone number was verified.
type VerificationData struct {
	PhoneNumber string
	User        *models.User
}

// SendOTPFunc delivers an OTP by SMS. request is the incoming HTTP request (nil outside HTTP).
type SendOTPFunc func(data OTPData, request *http.Request) error

// VerifyOTPFunc replaces the built-in code check (e.g. Twilio Verify). It returns whether the code is valid.
type VerifyOTPFunc func(data OTPData, request *http.Request) (bool, error)

// PhoneNumberValidatorFunc reports whether a phone number is acceptable (used by send-otp and sign-in).
type PhoneNumberValidatorFunc func(phoneNumber string) bool

// CallbackOnVerificationFunc runs after a phone number was verified (and the user created/updated).
type CallbackOnVerificationFunc func(data VerificationData, request *http.Request) error

// SignUpOnVerification creates a user when an unknown phone number is verified.
type SignUpOnVerification struct {
	// GetTempEmail returns the placeholder email of the new user (required by better-auth; email stays
	// required and unique). Defaults to "<phoneNumber>@phone.invalid" when nil.
	GetTempEmail func(phoneNumber string) string
	// GetTempName returns the new user's name. Defaults to the phone number.
	GetTempName func(phoneNumber string) string
}

// PhoneNumberConfig mirrors better-auth's phoneNumber() options.
type PhoneNumberConfig struct {
	// SendOTP sends the verification code. Without it POST /phone-number/send-otp answers 501.
	SendOTP SendOTPFunc
	// SendPasswordResetOTP sends the password reset code (POST /phone-number/request-password-reset).
	SendPasswordResetOTP SendOTPFunc
	// VerifyOTP replaces the built-in "code:attempts" check.
	VerifyOTP VerifyOTPFunc
	// PhoneNumberValidator rejects malformed numbers with 400 INVALID_PHONE_NUMBER.
	PhoneNumberValidator PhoneNumberValidatorFunc
	// OTPLength is the number of digits of generated codes (default 6).
	OTPLength int
	// ExpiresIn is how long a code is valid (default 300s).
	ExpiresIn time.Duration
	// AllowedAttempts is how many wrong codes are accepted before 403 TOO_MANY_ATTEMPTS (default 3).
	AllowedAttempts int
	// RequireVerification blocks password sign-in until the phone number is verified (an OTP is sent instead).
	RequireVerification bool
	// SignUpOnVerification creates users for unknown phone numbers on POST /phone-number/verify.
	SignUpOnVerification *SignUpOnVerification
	// CallbackOnVerification runs after every successful verification.
	CallbackOnVerification CallbackOnVerificationFunc
}

// WithDefaults returns cfg with better-auth's defaults filled in.
func (cfg PhoneNumberConfig) WithDefaults() PhoneNumberConfig {
	// Step 1: code length (better-auth: options.otpLength || 6)
	if cfg.OTPLength <= 0 {
		cfg.OTPLength = DefaultOTPLength
	}
	// Step 2: code lifetime (better-auth: options.expiresIn || 300 seconds)
	if cfg.ExpiresIn <= 0 {
		cfg.ExpiresIn = DefaultExpiresIn
	}
	// Step 3: attempts before lockout (better-auth: opts.allowedAttempts || 3)
	if cfg.AllowedAttempts <= 0 {
		cfg.AllowedAttempts = DefaultAllowedAttempts
	}
	return cfg
}
