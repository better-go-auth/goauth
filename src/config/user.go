package config

import (
	"net/http"
	"time"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/schema"
)

// UserOptions mirrors better-auth's `user` options.
type UserOptions struct {
	ChangeEmail ChangeEmailOptions
	DeleteUser  DeleteUserOptions

	// ModelName renames the user table (better-auth's user.modelName). It wins over GoAuth.TableNames.
	ModelName string
	// Fields renames user columns: field name → column name, used as is (better-auth's user.fields),
	// e.g. {"emailVerified": "is_verified"}.
	Fields map[string]string
	// AdditionalFields adds user fields stored in real columns (better-auth's user.additionalFields).
	AdditionalFields map[string]schema.Field

	GoAuth UserGoAuth
}

// UserGoAuth holds user options better-auth doesn't have.
type UserGoAuth struct {
	// SoftDelete keeps deleted users as tombstones (deletedAt set, email anonymized, phone number and
	// username released) instead of removing them. It applies to /delete-user, admin /remove-user and the
	// anonymous plugin. Default false: better-auth's hard delete, where the user's sessions, accounts and
	// plugin rows are removed with the user.
	SoftDelete bool
	// RejectUnknownUpdateFields makes /update-user fail with FIELD_NOT_ALLOWED ("Field <key> is not allowed to
	// be set") on body keys that are not fields of the user schema (goauth's old behaviour). Default false:
	// unknown keys are ignored, like better-auth. Schema fields always follow better-auth's input rules.
	RejectUnknownUpdateFields bool
}

// ChangeEmailOptions mirrors better-auth's `user.changeEmail`.
type ChangeEmailOptions struct {
	Enabled bool
	// UpdateEmailWithoutVerification lets unverified users change their email immediately.
	UpdateEmailWithoutVerification bool
	// SendChangeEmailConfirmation asks verified users to confirm the change from their current address first.
	SendChangeEmailConfirmation func(data ChangeEmailConfirmationData, request *http.Request) error
}

type ChangeEmailConfirmationData struct {
	User     models.User
	NewEmail string
	URL      string
	Token    string
}

// DeleteUserOptions mirrors better-auth's `user.deleteUser`.
type DeleteUserOptions struct {
	Enabled bool
	// SendDeleteAccountVerification makes delete-user email a confirmation link instead of deleting immediately.
	SendDeleteAccountVerification func(data DeleteAccountVerificationData, request *http.Request) error
	// DeleteTokenExpiresIn is how long the confirmation link is valid (default 24 hours).
	DeleteTokenExpiresIn time.Duration
	BeforeDelete         func(user models.User, request *http.Request) error
	AfterDelete          func(user models.User, request *http.Request) error
}

type DeleteAccountVerificationData struct {
	User  models.User
	URL   string
	Token string
}

// AccountOptions mirrors better-auth's `account` options.
type AccountOptions struct {
	AccountLinking AccountLinkingOptions

	// ModelName renames the account table (better-auth's account.modelName).
	ModelName string
	// Fields renames account columns: field name → column name (better-auth's account.fields).
	Fields map[string]string
	// AdditionalFields adds account fields (better-auth's account.additionalFields).
	AdditionalFields map[string]schema.Field

	// The OAuth options below configure the social plugin installed for AuthConfig.SocialProviders.

	// UpdateAccountOnSignIn refreshes the stored provider tokens on every sign-in (default true).
	UpdateAccountOnSignIn *bool
	// EncryptOAuthTokens stores provider access/refresh tokens encrypted with the auth secret.
	EncryptOAuthTokens bool
	// StoreStateStrategy is where the OAuth state lives between sign-in and callback: "database" (default) or
	// "cookie".
	StoreStateStrategy string
	// SkipStateCookieCheck skips the signed `state` cookie check of the database state strategy.
	SkipStateCookieCheck bool
	// StoreAccountCookie keeps the provider account of the last OAuth sign-in in the encrypted account_data
	// cookie, so /account-info works without accountId and the token endpoints skip a database read
	// (better-auth's account.storeAccountCookie).
	StoreAccountCookie bool
}

// AccountLinkingOptions mirrors better-auth's `account.accountLinking`.
type AccountLinkingOptions struct {
	// AllowUnlinkingAll allows unlinking the last account of a user.
	AllowUnlinkingAll bool
	// Enabled turns account linking on (default true).
	Enabled *bool
	// TrustedProviders may link even when the provider reports an unverified email.
	TrustedProviders []string
	// AllowDifferentEmails lets /link-social link an account whose email differs from the user's.
	AllowDifferentEmails bool
	// DisableImplicitLinking stops OAuth sign-in from linking a provider account to an existing user by email.
	DisableImplicitLinking bool
	// UpdateUserInfoOnLink copies the provider profile (name, image, ...) onto the user when linking.
	UpdateUserInfoOnLink bool
	// RequireLocalEmailVerified (default true) only links implicitly when the local user's email is verified.
	RequireLocalEmailVerified *bool
}
