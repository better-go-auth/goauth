package config

import (
	"net/http"
	"time"

	"github.com/better-go-auth/goauth/src/models"
)

type EmailVerification struct {
	// ExpiresIn is how long a verification link token is valid (default 1 hour).
	ExpiresIn time.Duration

	GoAuth EmailVerificationGoAuth

	// SendVerificationEmail sends better-auth's verification link (/verify-email?token=...).
	SendVerificationEmail SendVerificationEmail
	/**
	 * Send a verification email automatically after sign up.
	 *
	 * - `true`: Always send verification email on sign up
	 * - `false`: Never send verification email on sign up
	 * - `nil`: Follows `requireEmailVerification` behavior
	 *
	 * @default nil
	 */
	SendOnSignUp *bool
	/**
	 * Send a verification email automatically
	 * on sign in when the user's email is not verified
	 *
	 * @default false
	 */
	SendOnSignIn bool
	/**
	 * Auto signin the user after they verify their email
	 */
	AutoSignInAfterVerification bool
	/**
	 * A callback function that is triggered
	 * before a user's email is verified.
	 */
	BeforeEmailVerification func(user models.User, request *http.Request) error
	/**
	 * A callback function that is triggered
	 * after a user's email is verified successfully.
	 */
	AfterEmailVerification func(user models.User, request *http.Request) error
}

type (
	SendVerificationEmail func(data EmailVerificationData, request *http.Request) error
	GenerateCode          func() string
)

// EmailVerificationGoAuth configures goauth's 6-digit code flow.
type EmailVerificationGoAuth struct {
	CodeSender    VerificationSender
	CodeGenerator GenerateCode
	// CodeExpiresIn is how long a code is valid (default 15 minutes).
	CodeExpiresIn time.Duration
}

type EmailVerificationData struct {
	User  models.User
	URL   string
	Token string
}

type VerificationSender interface {
	SendVerificationCode(to string, code string) error
}
