package services

import (
	"net/http"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

// ErrorCodes are better-auth's ANONYMOUS_ERROR_CODES (code → message).
var ErrorCodes = map[string]string{
	"INVALID_EMAIL_FORMAT":                             "Email was not generated in a valid format",
	"FAILED_TO_CREATE_USER":                            "Failed to create user",
	"COULD_NOT_CREATE_SESSION":                         "Could not create session",
	"ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY": "Anonymous users cannot sign in again anonymously",
	"FAILED_TO_DELETE_ANONYMOUS_USER":                  "Failed to delete anonymous user",
	"FAILED_TO_DELETE_ANONYMOUS_USER_SESSIONS":         "Failed to delete anonymous user sessions",
	"USER_IS_NOT_ANONYMOUS":                            "User is not anonymous",
	"DELETE_ANONYMOUS_USER_DISABLED":                   "Deleting anonymous users is disabled",
}

// anonErr builds a plugin error with this plugin's message for code.
func anonErr(status int, code string) *autherr.AuthError {
	return pluginkit.NewError(status, code, ErrorCodes[code])
}

// Errors with the HTTP status better-auth throws them with.
var (
	ErrInvalidEmailFormat                  = anonErr(http.StatusBadRequest, "INVALID_EMAIL_FORMAT")
	ErrFailedToCreateUser                  = anonErr(http.StatusInternalServerError, "FAILED_TO_CREATE_USER")
	ErrCouldNotCreateSession               = anonErr(http.StatusBadRequest, "COULD_NOT_CREATE_SESSION")
	ErrCannotSignInAgainAnonymously        = anonErr(http.StatusBadRequest, "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY")
	ErrFailedToDeleteAnonymousUser         = anonErr(http.StatusInternalServerError, "FAILED_TO_DELETE_ANONYMOUS_USER")
	ErrFailedToDeleteAnonymousUserSessions = anonErr(http.StatusInternalServerError, "FAILED_TO_DELETE_ANONYMOUS_USER_SESSIONS")
	ErrUserIsNotAnonymous                  = anonErr(http.StatusForbidden, "USER_IS_NOT_ANONYMOUS")
	ErrDeleteAnonymousUserDisabled         = anonErr(http.StatusBadRequest, "DELETE_ANONYMOUS_USER_DISABLED")
)
