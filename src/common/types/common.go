// Package humatypes provides shared Huma adapter types used across all domain modules.
package humatypes

import (
	"net/http"
	"strings"

	erors "github.com/better-go-auth/goauth/src/common/error"

	"github.com/danielgtaylor/huma/v2"
)

func init() {
	// Override Huma's default RFC-9457 error model so that ALL error responses
	// (handler errors + request validation failures) use Better Auth's
	// {"code","message"} envelope.
	huma.NewError = func(status int, msg string, errs ...error) huma.StatusError {
		if status == http.StatusUnprocessableEntity {
			// Better Auth reports body-schema violations as 400 VALIDATION_ERROR
			// with a "[body.field] message; ..." summary, not 422.
			return &erors.AuthError{
				StatusCode: http.StatusBadRequest,
				Code:       erors.RespCode("VALIDATION_ERROR"),
				Message:    validationMessage(msg, errs),
			}
		}
		return &erors.AuthError{StatusCode: status, Code: erors.RespCode(erors.StatusCode(status)), Message: msg}
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
