package config

import (
	"net/http"

	"github.com/better-go-auth/goauth/src/models"
)

type EmailVerification struct {
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
	SendOnSignIn *bool
	/**
	 * Auto signin the user after they verify their email
	 */
	AutoSignInAfterVerification *bool
	/**
	 * Number of seconds the verification token is
	 * valid for.
	 * @default 3600 seconds (1 hour)
	 */
	ExpiresIn int
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

type SendVerificationEmail func(data EmailVerificationData, request *http.Request) error

type EmailVerificationData struct {
	User  models.User
	URL   string
	Token string
}
