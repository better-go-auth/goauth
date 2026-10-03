// Package humatypes provides shared Huma adapter types used across all domain modules.
package types

import (
	"net/http"
	"strings"
	"sync"

	erors "github.com/better-go-auth/goauth/src/common/errors"

	"github.com/danielgtaylor/huma/v2"
)

// opMetaKey marks operations registered by goauth (core and plugins).
const opMetaKey = "goauth"

// NewError builds goauth's Better Auth style error ({"code","message"}).
// Request body validation failures (422) are reported as 400 VALIDATION_ERROR, like Better Auth.
func NewError(status int, msg string, errs ...error) huma.StatusError {
	if status == http.StatusUnprocessableEntity {
		return &erors.AuthError{
			StatusCode: http.StatusBadRequest,
			Code:       erors.RespCode("VALIDATION_ERROR"),
			Message:    validationMessage(msg, errs),
		}
	}
	return &erors.AuthError{StatusCode: status, Code: erors.RespCode(erors.StatusCode(status)), Message: msg}
}

var scopedOnce, globalOnce sync.Once

// InstallScopedErrorHandler formats Huma-generated errors (validation, unexpected handler errors)
// with NewError for goauth operations only; all other operations keep the previous formatter.
func InstallScopedErrorHandler() {
	scopedOnce.Do(func() {
		prev := huma.NewErrorWithContext
		huma.NewErrorWithContext = func(ctx huma.Context, status int, msg string, errs ...error) huma.StatusError {
			if ctx != nil && IsGoauthOperation(ctx.Operation()) {
				return NewError(status, msg, errs...)
			}
			return prev(ctx, status, msg, errs...)
		}
	})
}

// InstallGlobalErrorOverride makes every Huma error in the process use NewError (pre-scoping behaviour).
func InstallGlobalErrorOverride() {
	globalOnce.Do(func() {
		huma.NewError = NewError
	})
}

// IsGoauthOperation reports whether op was registered through a WrapAPI API.
func IsGoauthOperation(op *huma.Operation) bool {
	return op != nil && op.Metadata[opMetaKey] == true
}

// WrapAPI returns an API that marks every operation registered through it as goauth-owned.
func WrapAPI(api huma.API) huma.API {
	if _, ok := api.(*goauthAPI); ok {
		return api
	}
	return &goauthAPI{API: api}
}

type goauthAPI struct {
	huma.API
}

func (a *goauthAPI) Adapter() huma.Adapter {
	return markingAdapter{Adapter: a.API.Adapter()}
}

// DocumentOperation keeps huma.Group prefixes and custom documenters working behind the wrapper.
func (a *goauthAPI) DocumentOperation(op *huma.Operation) {
	if d, ok := a.API.(huma.OperationDocumenter); ok {
		d.DocumentOperation(op)
		return
	}
	if !op.Hidden {
		a.API.OpenAPI().AddOperation(op)
	}
}

type markingAdapter struct {
	huma.Adapter
}

func (m markingAdapter) Handle(op *huma.Operation, handler func(ctx huma.Context)) {
	if op.Metadata == nil {
		op.Metadata = map[string]any{}
	}
	op.Metadata[opMetaKey] = true
	m.Adapter.Handle(op, handler)
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
