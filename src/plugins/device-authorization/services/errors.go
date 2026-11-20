package services

import (
	"net/http"

	"github.com/better-go-auth/goauth/src/plugins/device-authorization/dtos"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

// ErrorCodes are better-auth's DEVICE_AUTHORIZATION_ERROR_CODES (code → message). The endpoints send the
// messages as error_description of RFC 6749 style errors ({error, error_description}).
var ErrorCodes = map[string]string{
	"INVALID_DEVICE_CODE":           "Invalid device code",
	"EXPIRED_DEVICE_CODE":           "Device code has expired",
	"EXPIRED_USER_CODE":             "User code has expired",
	"AUTHORIZATION_PENDING":         "Authorization pending",
	"ACCESS_DENIED":                 "Access denied",
	"INVALID_USER_CODE":             "Invalid user code",
	"DEVICE_CODE_ALREADY_PROCESSED": "Device code already processed",
	"DEVICE_CODE_NOT_CLAIMED":       "Device code has not been claimed by a verifying session; call `GET /device` with the `user_code` while signed in before approving or denying",
	"POLLING_TOO_FREQUENTLY":        "Polling too frequently",
	"USER_NOT_FOUND":                "User not found",
	"FAILED_TO_CREATE_SESSION":      "Failed to create session",
	"INVALID_DEVICE_CODE_STATUS":    "Invalid device code status",
	"AUTHENTICATION_REQUIRED":       "Authentication required",
}

// OAuthError builds the {error, error_description} error better-auth's device endpoints throw.
func OAuthError(status int, code, description string) *pluginkit.BodyError {
	return pluginkit.NewBodyError(status, dtos.OAuthErrorBody{Error: code, ErrorDescription: description})
}

// OAuth error codes (the "error" member).
const (
	CodeInvalidRequest       = "invalid_request"
	CodeInvalidClient        = "invalid_client"
	CodeInvalidGrant         = "invalid_grant"
	CodeAuthorizationPending = "authorization_pending"
	CodeSlowDown             = "slow_down"
	CodeExpiredToken         = "expired_token"
	CodeAccessDenied         = "access_denied"
	CodeUnauthorized         = "unauthorized"
	CodeServerError          = "server_error"
)

// errWith builds an OAuth error whose description is the message of a DEVICE_AUTHORIZATION_ERROR_CODES code.
func errWith(status int, oauthCode, code string) *pluginkit.BodyError {
	return OAuthError(status, oauthCode, ErrorCodes[code])
}

// The errors of better-auth's device routes, with their HTTP status.
var (
	ErrInvalidClientID      = OAuthError(http.StatusBadRequest, CodeInvalidClient, "Invalid client ID")
	ErrInvalidGrantClientID = OAuthError(http.StatusBadRequest, CodeInvalidGrant, "Invalid client ID")
	ErrClientIDMismatch     = OAuthError(http.StatusBadRequest, CodeInvalidGrant, "Client ID mismatch")
	ErrInvalidDeviceCode    = errWith(http.StatusBadRequest, CodeInvalidGrant, "INVALID_DEVICE_CODE")
	ErrPollingTooFrequently = errWith(http.StatusBadRequest, CodeSlowDown, "POLLING_TOO_FREQUENTLY")
	ErrExpiredDeviceCode    = errWith(http.StatusBadRequest, CodeExpiredToken, "EXPIRED_DEVICE_CODE")
	ErrAuthorizationPending = errWith(http.StatusBadRequest, CodeAuthorizationPending, "AUTHORIZATION_PENDING")
	ErrAccessDeniedPoll     = errWith(http.StatusBadRequest, CodeAccessDenied, "ACCESS_DENIED")
	ErrUserNotFound         = errWith(http.StatusInternalServerError, CodeServerError, "USER_NOT_FOUND")
	ErrFailedToCreateSess   = errWith(http.StatusInternalServerError, CodeServerError, "FAILED_TO_CREATE_SESSION")
	ErrInvalidStatus        = errWith(http.StatusInternalServerError, CodeServerError, "INVALID_DEVICE_CODE_STATUS")
	ErrInvalidUserCode      = errWith(http.StatusBadRequest, CodeInvalidRequest, "INVALID_USER_CODE")
	ErrExpiredUserCode      = errWith(http.StatusBadRequest, CodeExpiredToken, "EXPIRED_USER_CODE")
	ErrAlreadyProcessed     = errWith(http.StatusBadRequest, CodeInvalidRequest, "DEVICE_CODE_ALREADY_PROCESSED")
	ErrNotClaimed           = errWith(http.StatusBadRequest, CodeInvalidRequest, "DEVICE_CODE_NOT_CLAIMED")
	ErrAuthenticationNeeded = errWith(http.StatusUnauthorized, CodeUnauthorized, "AUTHENTICATION_REQUIRED")
	ErrNotYourApproval      = OAuthError(http.StatusForbidden, CodeAccessDenied, "You are not authorized to approve this device authorization")
	ErrNotYourDenial        = OAuthError(http.StatusForbidden, CodeAccessDenied, "You are not authorized to deny this device authorization")
)
