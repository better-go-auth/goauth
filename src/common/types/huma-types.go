package types

import (
	"net/http"

	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/models/dtos"
)

// ─── Common types ─────────────────────────────────────────────────────────────

// type AuthParam struct {
// 	Auth string `header:"Authorization"`
// }

// AuthHeaders embeds an optional Bearer token header and session cookie.
type AuthHeaders struct {
	Authorization string `header:"Authorization" required:"false" doc:"Bearer session_token"`
	Cookie        string `header:"Cookie" required:"false" doc:"Session cookie"`
}

// ─── Request wrappers ─────────────────────────────────────────────────────────|
//                                                                               |
//_______________________________________________________________________________|

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

// ─── Response wrappers ─────────────────────────────────────────────────────────
//
//________________________________________________________________________________

// HumaRes is the response envelope for a Huma handler.
type HumaRes[T any] struct {
	Body       T             `json:"body" doc:"response Body"`
	Status     int           `json:"status,omitempty"`
	SetCookie  []http.Cookie `header:"Set-Cookie"`
	SetAuthJWT string        `header:"set-auth-jwt,omitempty"`
}

// MakeRes constructs a HumaRes, optionally attaching cookies.
func MakeRes[T any](body T, status int, setCookie ...http.Cookie) *HumaRes[T] {
	return &HumaRes[T]{Body: body, Status: status, SetCookie: setCookie}
}

func MakeResPtr[T any](item *T, status int, setCookie ...http.Cookie) *HumaRes[T] {
	if item == nil {
		var res T
		return &HumaRes[T]{
			Status: status,
			Body:   res,
		}
	}
	return &HumaRes[T]{
		Status: status,
		Body:   *item,
	}
}

// HumaGetSessionRes is the nullable get-session output: a nil Body serializes
// to the literal JSON `null`, matching Better Auth's unauthenticated response.
type HumaGetSessionRes = HumaRes[*dtos.SessionResponse]

type SuccessBody struct {
	Success bool `json:"success"`
}
type StatusBody struct {
	Status  bool   `json:"status"`
	Message string `json:"message,omitempty"`
}

type (
	StatusOutput  = HumaRes[StatusBody]
	SuccessOutput = HumaRes[SuccessBody]
)

type RedirectOutput struct {
	Location string `header:"Location"`
}

// MakeRes constructs a HumaRes, optionally attaching cookies.
func SuccessRes(status int, setCookie ...http.Cookie) *SuccessOutput {
	return &SuccessOutput{Body: SuccessBody{Success: true}, Status: status}
}

// ─── error response ─────────────────────────────────────────────────────────|
//_____________________________________________________________________________|

// RespondErr converts a better-go-auth error into a Better Auth-compatible
// HTTP error: proper status plus {"code","message"} body.
func RespondErr(err error) error {
	if authErr := autherr.AsAuthError(err); authErr != nil {
		return &autherr.AuthError{StatusCode: authErr.StatusCode, Code: authErr.Code, Message: authErr.Message}
	}
	return &autherr.AuthError{StatusCode: http.StatusInternalServerError, Code: "INTERNAL_SERVER_ERROR", Message: err.Error()}
}
