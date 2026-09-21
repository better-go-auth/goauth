package errors

import (
	"net/http"
	"strings"
)

type RespCode string

func (r RespCode) Msg() string {
	data := errorText[r]
	if data != "" {
		return data
	}
	return r.ToStr()
}

func (r RespCode) ToStr() string {
	return string(r)
}

// ─── Predefined errors (matching better-auth error codes) ────────────────────

var (
	ErrUserNotFound       = New(UserNotFound, UserNotFound.Msg(), http.StatusNotFound)
	ErrInvalidCredentials = New(InvalidCredentials, InvalidCredentials.Msg(), http.StatusUnauthorized)
	ErrEmailNotVerified   = New(EmailNotVerified, EmailNotVerified.Msg(), http.StatusForbidden)
	ErrUserBanned         = New(UserBanned, UserBanned.Msg(), http.StatusForbidden)
	ErrEmailExists        = New(EmailExists, EmailExists.Msg(), http.StatusUnprocessableEntity)
	ErrInvalidToken       = New(InvalidToken, InvalidToken.Msg(), http.StatusBadRequest)
	ErrSessionNotFound    = New(SessionNotFound, SessionNotFound.Msg(), http.StatusNotFound)
	ErrSessionExpired     = New(SessionExpired, SessionExpired.Msg(), http.StatusUnauthorized)
	ErrUnauthorized       = New(Unauthorized, Unauthorized.Msg(), http.StatusUnauthorized)
	ErrForbidden          = New(Forbidden, Forbidden.Msg(), http.StatusForbidden)
	ErrWeakPassword       = New(WeakPassword, WeakPassword.Msg(), http.StatusBadRequest)

	//
	ErrInvalidEmail     = New(InvalidEmail, InvalidEmail.Msg(), http.StatusBadRequest)
	ErrPasswordTooShort = New(PasswordTooShort, PasswordTooShort.Msg(), http.StatusBadRequest)
	ErrPasswordTooLong  = New(PasswordTooLong, PasswordTooLong.Msg(), http.StatusBadRequest)
	ErrProviderNotFound = New(ProviderNotFound, ProviderNotFound.Msg(), http.StatusNotFound)
	ErrInternal         = New(InternalError, InternalError.Msg(), http.StatusInternalServerError)
	ErrTokenExpired     = New(TokenExpired, TokenExpired.Msg(), http.StatusUnauthorized)
	ErrInvalidPassword  = New(InvalidPassword, InvalidPassword.Msg(), http.StatusBadRequest)
	ErrSessionNotFresh  = New(SessionNotFresh, SessionNotFresh.Msg(), http.StatusForbidden)
	ErrTokenDontMatch   = New(TokenDontMatch, TokenDontMatch.Msg(), http.StatusBadRequest)
	ErrInfoOrCode       = New(InfoOrCode, InfoOrCode.Msg(), http.StatusBadRequest)
	ErrUserExists       = New(UserExists, UserExists.Msg(), http.StatusConflict)
	ErrDataNotFound     = New(RecordNotFound, RecordNotFound.Msg(), http.StatusNotFound)

	// Compatibility aliases
	EmailOrPasswordErr  = ErrInvalidCredentials
	PwdDontMatch        = ErrInvalidPassword
	UserExistError      = ErrUserExists
	UserNotFoundError   = ErrUserNotFound
	DataNotFoundError   = ErrDataNotFound
	TokenDontMatchError = ErrTokenDontMatch
	InvalidTokenError   = ErrInvalidToken
	InfoOrCodeErr       = ErrInfoOrCode
	EmailExistsErr      = ErrEmailExists
)

func StatusCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "BAD_REQUEST"
	case http.StatusUnauthorized:
		return "UNAUTHORIZED"
	case http.StatusPaymentRequired:
		return "PAYMENT_REQUIRED"
	case http.StatusForbidden:
		return "FORBIDDEN"
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusMethodNotAllowed:
		return "METHOD_NOT_ALLOWED"
	case http.StatusNotAcceptable:
		return "NOT_ACCEPTABLE"
	case http.StatusConflict:
		return "CONFLICT"
	case http.StatusGone:
		return "GONE"
	case http.StatusUnsupportedMediaType:
		return "UNSUPPORTED_MEDIA_TYPE"
	case http.StatusTeapot:
		return "IM_A_TEAPOT"
	case http.StatusInternalServerError:
		return "INTERNAL_SERVER_ERROR"
	case http.StatusNotImplemented:
		return "NOT_IMPLEMENTED"
	case http.StatusBadGateway:
		return "BAD_GATEWAY"
	case http.StatusServiceUnavailable:
		return "SERVICE_UNAVAILABLE"
	case http.StatusInsufficientStorage:
		return "INSUFFICIENT_STORAGE"
	default:
		return strings.ToUpper(strings.ReplaceAll(http.StatusText(status), " ", "_"))
	}
}
