package autherr

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
)

// RequestIDHeader is the header that carries the request ID of an internal error (and is read from
// the incoming request when a proxy already set one).
const RequestIDHeader = "X-Request-Id"

// InternalMessage is the only message clients see for unexpected errors.
const InternalMessage = "Internal Server Error"

type requestIDKey struct{}

// WithRequestID stores the request ID of the incoming request in ctx, so Internal reuses it.
func WithRequestID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestIDFrom returns the request ID stored by WithRequestID, or "".
func RequestIDFrom(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// NewRequestID returns a random 16-byte hex request ID.
func NewRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Internal turns an unexpected error (a repository/driver error, a failed network call, ...) into a
// 500 INTERNAL_SERVER_ERROR that never shows the cause to the client. The cause is logged together with a
// request ID, and the same ID is returned in the body (requestId) and the X-Request-Id header.
//
// An *AuthError below 500 is returned unchanged: it is an expected, client-facing error.
func Internal(ctx context.Context, cause error) *AuthError {
	// Step 1: expected errors pass through
	if ae := AsAuthError(cause); ae != nil && ae.StatusCode > 0 && ae.StatusCode < http.StatusInternalServerError {
		return ae
	}
	// Step 2: reuse the incoming request ID when there is one
	id := RequestIDFrom(ctx)
	if id == "" {
		id = NewRequestID()
	}
	// Step 3: log the real cause server-side only
	if cause == nil {
		cause = errors.New("unknown error")
	}
	slog.Error("goauth: internal error", slog.String("requestId", id), slog.String("error", cause.Error()))
	// Step 4: keep an explicit better-auth 5xx code (FAILED_TO_CREATE_USER, ...) but never its cause
	if ae := AsAuthError(cause); ae != nil {
		return &AuthError{StatusCode: ae.StatusCode, Code: ae.Code, Message: ae.Message, RequestID: id}
	}
	return &AuthError{StatusCode: http.StatusInternalServerError, Code: "INTERNAL_SERVER_ERROR", Message: InternalMessage, RequestID: id}
}
