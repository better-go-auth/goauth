package services

import (
	"net/http"

	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

// better-auth TWO_FACTOR_ERROR_CODES (statuses as thrown by the endpoints).
var (
	ErrOTPNotEnabled          = pluginkit.NewError(http.StatusBadRequest, "OTP_NOT_ENABLED", "OTP not enabled")
	ErrOTPHasExpired          = pluginkit.NewError(http.StatusBadRequest, "OTP_HAS_EXPIRED", "OTP has expired")
	ErrTOTPNotEnabled         = pluginkit.NewError(http.StatusBadRequest, "TOTP_NOT_ENABLED", "TOTP not enabled")
	ErrTwoFactorNotEnabled    = pluginkit.NewError(http.StatusBadRequest, "TWO_FACTOR_NOT_ENABLED", "Two factor isn't enabled")
	ErrBackupCodesNotEnabled  = pluginkit.NewError(http.StatusBadRequest, "BACKUP_CODES_NOT_ENABLED", "Backup codes aren't enabled")
	ErrInvalidBackupCode      = pluginkit.NewError(http.StatusUnauthorized, "INVALID_BACKUP_CODE", "Invalid backup code")
	ErrInvalidBackupCodeView  = pluginkit.NewError(http.StatusBadRequest, "INVALID_BACKUP_CODE", "Invalid backup code")
	ErrInvalidCode            = pluginkit.NewError(http.StatusUnauthorized, "INVALID_CODE", "Invalid code")
	ErrTooManyAttempts        = pluginkit.NewError(http.StatusBadRequest, "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE", "Too many attempts. Please request a new code.")
	ErrInvalidTwoFactorCookie = pluginkit.NewError(http.StatusUnauthorized, "INVALID_TWO_FACTOR_COOKIE", "Invalid two factor cookie")

	// Inline errors of the endpoints.
	ErrTOTPNotConfigured     = pluginkit.NewError(http.StatusBadRequest, "TOTP_NOT_CONFIGURED", "totp isn't configured")
	ErrOTPNotConfigured      = pluginkit.NewError(http.StatusBadRequest, "OTP_NOT_CONFIGURED", "otp isn't configured")
	ErrBackupCodeConflict    = pluginkit.NewError(http.StatusConflict, "CONFLICT", "Failed to verify backup code. Please try again.")
	ErrFailedToCreateSession = pluginkit.NewError(http.StatusBadRequest, "FAILED_TO_CREATE_SESSION", "Failed to create session")
	ErrInvalidPassword       = pluginkit.NewError(http.StatusBadRequest, "INVALID_PASSWORD", "Invalid password")
	// ErrPasswordRequired is the body validation error when password is missing and allowPasswordless is off.
	ErrPasswordRequired = pluginkit.NewError(http.StatusBadRequest, "VALIDATION_ERROR", "[body.password] Invalid input: expected string, received undefined")
)
