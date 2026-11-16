package services

import (
	"net/http"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

// ErrorCodes are better-auth's PHONE_NUMBER_ERROR_CODES (code → message).
var ErrorCodes = map[string]string{
	"INVALID_PHONE_NUMBER":             "Invalid phone number",
	"PHONE_NUMBER_EXIST":               "Phone number already exists",
	"PHONE_NUMBER_NOT_EXIST":           "phone number isn't registered",
	"INVALID_PHONE_NUMBER_OR_PASSWORD": "Invalid phone number or password",
	"UNEXPECTED_ERROR":                 "Unexpected error",
	"OTP_NOT_FOUND":                    "OTP not found",
	"OTP_EXPIRED":                      "OTP expired",
	"INVALID_OTP":                      "Invalid OTP",
	"PHONE_NUMBER_NOT_VERIFIED":        "Phone number not verified",
	"PHONE_NUMBER_CANNOT_BE_UPDATED":   "Phone number cannot be updated",
	"SEND_OTP_NOT_IMPLEMENTED":         "sendOTP not implemented",
	"TOO_MANY_ATTEMPTS":                "Too many attempts",
}

func phoneErr(status int, code string) *autherr.AuthError {
	return pluginkit.NewError(status, code, ErrorCodes[code])
}

// Errors with the HTTP status better-auth throws them with. They are built with pluginkit.NewError so codes
// shared with other plugins (INVALID_OTP, OTP_EXPIRED, TOO_MANY_ATTEMPTS) keep this plugin's messages.
var (
	ErrInvalidPhoneNumber            = phoneErr(http.StatusBadRequest, "INVALID_PHONE_NUMBER")
	ErrPhoneNumberExist              = phoneErr(http.StatusBadRequest, "PHONE_NUMBER_EXIST")
	ErrInvalidPhoneNumberOrPassword  = phoneErr(http.StatusUnauthorized, "INVALID_PHONE_NUMBER_OR_PASSWORD")
	ErrUnexpected                    = phoneErr(http.StatusUnauthorized, "UNEXPECTED_ERROR")
	ErrUnexpectedBadRequest          = phoneErr(http.StatusBadRequest, "UNEXPECTED_ERROR")
	ErrOTPNotFound                   = phoneErr(http.StatusBadRequest, "OTP_NOT_FOUND")
	ErrOTPExpired                    = phoneErr(http.StatusBadRequest, "OTP_EXPIRED")
	ErrInvalidOTP                    = phoneErr(http.StatusBadRequest, "INVALID_OTP")
	ErrPhoneNumberNotVerified        = phoneErr(http.StatusUnauthorized, "PHONE_NUMBER_NOT_VERIFIED")
	ErrPhoneNumberCannotBeUpdated    = phoneErr(http.StatusBadRequest, "PHONE_NUMBER_CANNOT_BE_UPDATED")
	ErrSendOTPNotImplemented         = phoneErr(http.StatusNotImplemented, "SEND_OTP_NOT_IMPLEMENTED")
	ErrTooManyAttempts               = phoneErr(http.StatusForbidden, "TOO_MANY_ATTEMPTS")
	ErrNoSessionForUpdate            = autherr.ErrUserNotFound.WithStatus(http.StatusUnauthorized)
	ErrPhoneNumberVerifiedNotAllowed = autherr.ErrFieldNotAllowed.WithMessage("phoneNumberVerified is not allowed to be set")
)
