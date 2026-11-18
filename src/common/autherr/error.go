package autherr

import (
	"errors"
	"fmt"
	"net/http"
)

// AuthError is a typed error with an HTTP status code and a machine-readable code.
// this JSON body matches Better Auth's wire format: {"code": "...", "message": "..."}.
type AuthError struct {
	StatusCode int      `json:"-"`
	Code       RespCode `json:"code,omitempty"`
	Message    string   `json:"message"`
	// RequestID is set on internal (5xx) errors created by Internal; the same ID is logged with the
	// real cause, so a client report can be matched to the log.
	RequestID string `json:"requestId,omitempty"`
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}
func (e *AuthError) GetStatus() int { return e.StatusCode }

// AuthError deliberately does not implement huma.HeadersError: huma.ErrorWithHeaders merges headers into
// the error's own map, and most AuthErrors are shared package variables. The request ID of an internal
// error is sent in the body (requestId) and, where the HTTP context is at hand, in X-Request-Id.

// Is implements errors.Is for AuthError comparison by code.
func (e *AuthError) Is(target error) bool {
	t, ok := target.(*AuthError)
	if !ok {
		return false
	}
	return e.Code == t.Code
}

// New creates a new AuthError instance.
func New(code RespCode, message string, status int) *AuthError {
	return &AuthError{StatusCode: status, Code: code, Message: message}
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
