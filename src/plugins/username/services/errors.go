package services

import (
	"net/http"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

// ErrorCodes are better-auth's USERNAME_ERROR_CODES (code → message).
var ErrorCodes = map[string]string{
	"INVALID_USERNAME_OR_PASSWORD": "Invalid username or password",
	"EMAIL_NOT_VERIFIED":           "Email not verified",
	"UNEXPECTED_ERROR":             "Unexpected error",
	"USERNAME_IS_ALREADY_TAKEN":    "Username is already taken. Please try another.",
	"USERNAME_TOO_SHORT":           "Username is too short",
	"USERNAME_TOO_LONG":            "Username is too long",
	"INVALID_USERNAME":             "Username is invalid",
	"INVALID_DISPLAY_USERNAME":     "Display username is invalid",
}

// usernameErr builds a plugin error with this plugin's message for code.
func usernameErr(status int, code string) *autherr.AuthError {
	return pluginkit.NewError(status, code, ErrorCodes[code])
}

// Errors with the HTTP status better-auth throws them with. Validation errors are 400 in the sign-up /
// update-user hooks and 422 on /sign-in/username and /is-username-available.
var (
	ErrInvalidUsernameOrPassword = usernameErr(http.StatusUnauthorized, "INVALID_USERNAME_OR_PASSWORD")
	ErrEmailNotVerified          = usernameErr(http.StatusForbidden, "EMAIL_NOT_VERIFIED")
	ErrUsernameTaken             = usernameErr(http.StatusBadRequest, "USERNAME_IS_ALREADY_TAKEN")
	ErrUsernameTooShort          = usernameErr(http.StatusBadRequest, "USERNAME_TOO_SHORT")
	ErrUsernameTooLong           = usernameErr(http.StatusBadRequest, "USERNAME_TOO_LONG")
	ErrInvalidUsername           = usernameErr(http.StatusBadRequest, "INVALID_USERNAME")
	ErrInvalidDisplayUsername    = usernameErr(http.StatusBadRequest, "INVALID_DISPLAY_USERNAME")
)
