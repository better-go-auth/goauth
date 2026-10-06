package config

import (
	"net/http"

	"github.com/better-go-auth/goauth/src/models"
)

// UserOptions mirrors better-auth's `user` options.
type UserOptions struct {
	ChangeEmail ChangeEmailOptions
	DeleteUser  DeleteUserOptions
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

// DeleteUserOptions mirrors better-auth's `user.deleteUser` (without the email confirmation flow).
type DeleteUserOptions struct {
	Enabled      bool
	BeforeDelete func(user models.User, request *http.Request) error
	AfterDelete  func(user models.User, request *http.Request) error
}

// AccountOptions mirrors better-auth's `account` options.
type AccountOptions struct {
	AccountLinking AccountLinkingOptions
}

type AccountLinkingOptions struct {
	// AllowUnlinkingAll allows unlinking the last account of a user.
	AllowUnlinkingAll bool
}
