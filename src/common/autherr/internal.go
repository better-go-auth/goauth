package autherr

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"sync/atomic"

	"github.com/better-go-auth/goauth/src/common/logger"
)

// exposeRequestID is config Advanced.GoAuth.ErrorRequestID (process-wide, set by SetupGoAuth): when true,
// internal errors carry their request ID in the body (requestId) and the X-Request-Id header.
var exposeRequestID atomic.Bool

// SetExposeRequestID sets whether internal errors show their request ID to the client (default false:
// better-auth's plain {code, message} body; the ID is still logged with the cause).
func SetExposeRequestID(expose bool) { exposeRequestID.Store(expose) }

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
// request ID; with SetExposeRequestID(true) the same ID is also returned in the body (requestId) and the
// X-Request-Id header.
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
	// Step 3: log the real cause server-side only; when AuthConfig.OnAPIError.OnError / Throw is set the
	// app gets it instead (better-auth's router hands non-API errors to onError instead of logging them)
	if cause == nil {
		cause = errors.New("unknown error")
	}
	if report := reporterFrom(ctx); report != nil && AsAuthError(cause) == nil {
		report(&ReportedError{RequestID: id, Err: cause})
	} else {
		logger.Error("goauth: internal error", "requestId", id, "error", cause.Error())
	}
	// the client only sees the ID when config Advanced.GoAuth.ErrorRequestID is on
	if !exposeRequestID.Load() {
		id = ""
	}
	// Step 4: keep an explicit better-auth 5xx code (FAILED_TO_CREATE_USER, ...) but never its cause
	if ae := AsAuthError(cause); ae != nil {
		return &AuthError{StatusCode: ae.StatusCode, Code: ae.Code, Message: ae.Message, RequestID: id}
	}
	return &AuthError{StatusCode: http.StatusInternalServerError, Code: "INTERNAL_SERVER_ERROR", Message: InternalMessage, RequestID: id}
}

// ReportedError is what an error Reporter (AuthConfig.OnAPIError.OnError) receives for an unexpected
// error: the cause and the request ID it was logged / answered with. errors.Is / errors.As reach the cause.
type ReportedError struct {
	RequestID string
	Err       error
}

func (e *ReportedError) Error() string { return e.Err.Error() }

// Unwrap returns the cause.
func (e *ReportedError) Unwrap() error { return e.Err }

// Reporter receives the errors better-auth's router passes to onAPIError.onError: unexpected (500) errors
// and errors raised before the endpoint runs (origin check, endpoint before-hooks).
type Reporter func(err error)

type reporterKey struct{}

// WithReporter stores an error reporter in ctx (SetupGoAuth installs one per request when
// AuthConfig.OnAPIError.OnError or Throw is set).
func WithReporter(ctx context.Context, r Reporter) context.Context {
	if r == nil {
		return ctx
	}
	return context.WithValue(ctx, reporterKey{}, r)
}

// reporterFrom returns the reporter stored by WithReporter, or nil.
func reporterFrom(ctx context.Context) Reporter {
	if ctx == nil {
		return nil
	}
	r, _ := ctx.Value(reporterKey{}).(Reporter)
	return r
}

// Report hands err to the reporter stored in ctx and reports whether there was one.
func Report(ctx context.Context, err error) bool {
	r := reporterFrom(ctx)
	if r == nil || err == nil {
		return false
	}
	r(err)
	return true
}
