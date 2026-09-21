package errors

import (
	"errors"
	"fmt"
	"net/http"
)

// AuthError is a typed error with an HTTP status code and a machine-readable code.
// this JSON body matches Better Auth's wire format: {"code": "...", "message": "..."}.
type AuthError struct {
	StatusCode int      `json:"-"`
	Code       RespCode `json:"code"`
	Message    string   `json:"message"`
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}
func (e *AuthError) GetStatus() int { return e.StatusCode }

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
