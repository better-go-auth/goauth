// Package humatypes provides shared Huma adapter types used across all domain modules.
package humatypes

import (
	"net/http"
	"strings"

	"github.com/better-go-auth/goauth/src/models/dtos"
	autherr "github.com/better-go-auth/goauth/src/common/error"
	"github.com/danielgtaylor/huma/v2"
)

// HumaRes is the response envelope for a Huma handler.
type HumaRes[T any] struct {
	Body       T `json:"body" doc:"response Body"`
	Status     int
	SetCookie  []http.Cookie `header:"Set-Cookie"`
	SetAuthJWT string        `header:"set-auth-jwt,omitempty"`
}

// MakeRes constructs a HumaRes, optionally attaching cookies.
func MakeRes[T any](body T, status int, setCookie ...http.Cookie) HumaRes[T] {
	return HumaRes[T]{Body: body, Status: status, SetCookie: setCookie}
}

// MakeRes constructs a HumaRes, optionally attaching cookies.
func SuccessRes[T any](body T, setCookie ...http.Cookie) SuccessOutput {
	return SuccessOutput{Body: SuccessBody{Success: true}}
}

// Ptr returns a pointer to v — avoids temp vars in handler return statements.
func Ptr[T any](v T) *T { return &v }

// AuthStatusError is a Huma StatusError whose JSON body matches Better Auth's
// wire format: {"code": "...", "message": "..."}.
type AuthStatusError struct {
	Status  int    `json:"-"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
}

func (e *AuthStatusError) Error() string {
	return "[" + e.Code + "] " + e.Message
}

// GetStatus implements huma.StatusError.
func (e *AuthStatusError) GetStatus() int { return e.Status }

// NewAuthStatusError builds an AuthStatusError from status/code/message.
func NewAuthStatusError(status int, code, message string) *AuthStatusError {
	return &AuthStatusError{Status: status, Code: code, Message: message}
}

func init() {
	// Override Huma's default RFC-9457 error model so that ALL error responses
	// (handler errors + request validation failures) use Better Auth's
	// {"code","message"} envelope.
	huma.NewError = func(status int, msg string, errs ...error) huma.StatusError {
		if status == http.StatusUnprocessableEntity {
			// Better Auth reports body-schema violations as 400 VALIDATION_ERROR
			// with a "[body.field] message; ..." summary, not 422.
			return &AuthStatusError{
				Status:  http.StatusBadRequest,
				Code:    "VALIDATION_ERROR",
				Message: validationMessage(msg, errs),
			}
		}
		return &AuthStatusError{Status: status, Code: statusCode(status), Message: msg}
	}
}

func statusCode(status int) string {
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

// validationMessage mirrors Better Auth's zod-style validation summary:
// "[body.name] Invalid input: ...; [body.email] Invalid email address".
func validationMessage(fallback string, errs []error) string {
	parts := make([]string, 0, len(errs))
	for _, e := range errs {
		if ed, ok := e.(huma.ErrorDetailer); ok {
			d := ed.ErrorDetail()
			if d.Location != "" {
				parts = append(parts, "["+d.Location+"] "+d.Message)
				continue
			}
			parts = append(parts, d.Message)
			continue
		}
		parts = append(parts, e.Error())
	}
	if len(parts) == 0 {
		return fallback
	}
	return strings.Join(parts, "; ")
}

// RespondErr converts a better-go-auth error into a Better Auth-compatible
// HTTP error: proper status plus {"code","message"} body.
func RespondErr(err error) error {
	if authErr := autherr.AsAuthError(err); authErr != nil {
		return &AuthStatusError{Status: authErr.StatusCode, Code: string(authErr.Code), Message: authErr.Message}
	}
	return &AuthStatusError{Status: http.StatusInternalServerError, Code: "INTERNAL_SERVER_ERROR", Message: err.Error()}
}

// ─── Request wrappers ─────────────────────────────────────────────────────────

// HumaReqBody wraps a typed body with standard auth + device headers.
type HumaReqBody[T any] struct {
	AuthHeaders
	Body      T      `json:"body" doc:"request Body"`
	UserAgent string `header:"User-Agent,omitempty"`
	XRealIP   string `header:"X-Real-IP,omitempty"`
}

// HumaReqId is for requests that carry only a path ID (GET / DELETE).
type HumaReqId struct {
	ID   string `path:"id"`
	Auth string `header:"Authorization"`
}

// HumaReqBodyId is for requests that carry a path ID and a JSON body (PATCH).
type HumaReqBodyId[T any] struct {
	ID   string `path:"id"`
	Body T      `json:"body" doc:",request Body"`
	Auth string `header:"Authorization"`
}

// HumaReqEmpty is for requests that only require authentication (no body, no path ID).
type HumaReqEmpty struct {
	AuthHeaders
}

// ─── Common types ─────────────────────────────────────────────────────────────

type AuthParam struct {
	Auth string `header:"Authorization"`
}

// AuthHeaders embeds an optional Bearer token header and session cookie.
type AuthHeaders struct {
	Authorization string `header:"Authorization" required:"false" doc:"Bearer session_token"`
	Cookie        string `header:"Cookie" required:"false" doc:"Session cookie"`
}

// HumaGetSessionRes is the nullable get-session output: a nil Body serializes
// to the literal JSON `null`, matching Better Auth's unauthenticated response.
type HumaGetSessionRes = HumaRes[*dtos.SessionResponse]

type SuccessBody struct {
	Success bool `json:"success"`
}

type SuccessOutput struct {
	Body      SuccessBody
	SetCookie []http.Cookie `header:"Set-Cookie"`
}

type StatusBody struct {
	Status  bool   `json:"status"`
	Message string `json:"message,omitempty"`
}

type StatusOutput struct {
	Body      StatusBody
	SetCookie []http.Cookie `header:"Set-Cookie"`
}

type RedirectOutput struct {
	Location string `header:"Location"`
}
