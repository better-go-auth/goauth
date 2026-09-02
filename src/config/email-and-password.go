package config

import (
	"net/http"
	"time"

	"github.com/better-go-auth/goauth/src/models"
)

type EmailAndPassword struct {
	/**
	 * Enable email and password authentication
	 *
	 * @default false
	 */
	Enabled *bool
	/**
	 * Disable email and password sign up
	 *
	 * @default false
	 */
	DisableSignUp bool
	/**
	 * Require email verification before a session
	 * can be created for the user.
	 *
	 * if the user is not verified, the user will not be able to sign in
	 * and on sign in attempts, the user will be prompted to verify their email.
	 */
	RequireEmailVerification bool
	/**
	 * The maximum length of the password.
	 *
	 * @default 128
	 */
	MaxPasswordLength int
	/**
	 * The minimum length of the password.
	 *
	 * @default 8
	 */
	MinPasswordLength int
	/**
	 * send reset password
	 */
	SendResetPassword SendResetPasswordFunc
	/**
	 * Number of seconds the reset password token is
	 * valid for.
	 * @default 1 hour (60 * 60)
	 */
	ResetPasswordTokenExpiresIn time.Duration
	/**
	 * A callback function that is triggered
	 * when a user's password is changed successfully.
	 */
	// OnPasswordReset OnPasswordResetFunc
	/**
	 * Password hashing and verification
	 *
	 * By default Scrypt is used for password hashing and
	 * verification. You can provide your own hashing and
	 * verification function. if you want to use a
	 * different algorithm.
	 */
	// Password *PasswordHasher
	/**
	 * Automatically sign in the user after sign up
	 *
	 * @default true
	 */
	AutoSignIn *bool
	/**
	 * Whether to revoke all other sessions when resetting password
	 * @default false
	 */
	RevokeSessionsOnPasswordReset bool
	/**
	 * A callback function that is triggered when a user tries to sign up
	 * with an email that already exists. Useful for notifying the existing user
	 * that someone attempted to register with their email.
	 *
	 * This is only called when `requireEmailVerification: true` or `autoSignIn: false`.
	 */
	OnExistingUserSignUp OnExistingUserSignUpFunc
	/**
		 * Build a custom synthetic user for email enumeration
		 * protection. When a sign-up attempt is made with an
		 * email that already exists, this function is called
		 * to build the fake user response.
		 *
		 * Use this when plugins add fields to the user table
		 * (e.g. admin plugin adds `role`, `banned`, etc.)
		 * to ensure the fake response is indistinguishable
		 * from a real sign-up.

		     * @example
	     * ```ts
	     * customSyntheticUser: ({ coreFields, additionalFields, id }) => ({
	     *   ...coreFields,
	     *   role: "user",
	     *   banned: false,
	     *   banReason: null,
	     *   banExpires: null,
	     *   ...additionalFields,
	     *   id,
	     * })
	*/
	// CustomSyntheticUser CustomSyntheticUserFunc
}

type SendResetPasswordFunc func(data ResetPasswordData, request *http.Request) error

type ResetPasswordData struct {
	User  models.User
	URL   string
	Token string
}

type OnPasswordResetFunc func(data PasswordResetData, request *http.Request) error

type PasswordResetData struct {
	User models.User
}

type PasswordHasher struct {
	Hash   func(password string) (string, error)
	Verify func(hash string, password string) (bool, error)
}

type OnExistingUserSignUpFunc func(data ExistingUserSignUpData, request *http.Request) error

type ExistingUserSignUpData struct {
	User models.User
}
