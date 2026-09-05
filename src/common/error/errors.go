package errors

import (
	"errors"
	"fmt"
	"net/http"
)

// AuthError is a typed error with an HTTP status code and a machine-readable code.
type AuthError struct {
	Code       RespCode `json:"code"`
	Message    string   `json:"message"`
	StatusCode int      `json:"-"`
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Is implements errors.Is for AuthError comparison by code.
func (e *AuthError) Is(target error) bool {
	t, ok := target.(*AuthError)
	if !ok {
		return false
	}
	return e.Code == t.Code
}

// New creates a new AuthError.
func New(code RespCode, message string, status int) *AuthError {
	return &AuthError{Code: code, Message: message, StatusCode: status}
}
func NotFoundErr(message string) *AuthError {
	return &AuthError{Code: RecordNotFound, Message: message, StatusCode: http.StatusNotFound}
}

// IsAuthError returns true if the error is an *AuthError.
func IsAuthError(err error) bool {
	var e *AuthError
	return errors.As(err, &e)
}

// AsAuthError unwraps an error as *AuthError. Returns nil if not an AuthError.
func AsAuthError(err error) *AuthError {
	var e *AuthError
	if errors.As(err, &e) {
		return e
	}
	return nil
}

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
	ErrOrgNotFound        = New(OrgNotFound, OrgNotFound.Msg(), http.StatusNotFound)
	ErrMemberNotFound     = New(MemberNotFound, MemberNotFound.Msg(), http.StatusNotFound)
	ErrAlreadyMember      = New(AlreadyMember, AlreadyMember.Msg(), http.StatusBadRequest)
	ErrInvitationNotFound = New(InvitationNotFound, InvitationNotFound.Msg(), http.StatusNotFound)
	ErrInvitationExpired  = New(InvitationExpired, InvitationExpired.Msg(), http.StatusBadRequest)
	ErrSlugTaken          = New(SlugTaken, SlugTaken.Msg(), http.StatusUnprocessableEntity)
	ErrInvalidEmail       = New(InvalidEmail, InvalidEmail.Msg(), http.StatusBadRequest)
	ErrPasswordTooShort   = New(PasswordTooShort, PasswordTooShort.Msg(), http.StatusBadRequest)
	ErrPasswordTooLong    = New(PasswordTooLong, PasswordTooLong.Msg(), http.StatusBadRequest)
	ErrProviderNotFound   = New(ProviderNotFound, ProviderNotFound.Msg(), http.StatusNotFound)
	ErrInternal           = New(InternalError, InternalError.Msg(), http.StatusInternalServerError)
	ErrTokenExpired       = New(TokenExpired, TokenExpired.Msg(), http.StatusUnauthorized)
	ErrInvalidPassword    = New(InvalidPassword, InvalidPassword.Msg(), http.StatusBadRequest)
	ErrSessionNotFresh    = New(SessionNotFresh, SessionNotFresh.Msg(), http.StatusForbidden)
)
