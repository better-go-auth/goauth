// Package humatypes provides shared Huma adapter types used across all domain modules.
package types

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	erors "github.com/better-go-auth/goauth/src/common/autherr"

	"github.com/danielgtaylor/huma/v2"
)

// opMetaKey marks operations registered by goauth (core and plugins).
const opMetaKey = "goauth"

// RawBodyMetaKey marks operations whose bodies must reach the client untouched (no $schema links or other
// host transformers), as better-auth clients expect exact payloads.
const RawBodyMetaKey = "goauth.rawBody"

// SkipOriginCheckMetaKey marks operations that skip the Origin/Referer CSRF check, better-auth's
// skipOriginCheck paths (e.g. SAML endpoints receiving cross-site POSTs from an identity provider).
const SkipOriginCheckMetaKey = "goauth.skipOriginCheck"

// NewError builds goauth's Better Auth style error ({"code","message"}).
// Request body validation failures (422) are reported as 400 VALIDATION_ERROR, like Better Auth.
func NewError(status int, msg string, errs ...error) huma.StatusError {
	return newError(context.Background(), status, msg, errs...)
}

// newError is NewError with the request context, used to reuse the incoming request ID.
func newError(ctx context.Context, status int, msg string, errs ...error) huma.StatusError {
	// Step 1: unexpected handler errors: log the cause with a request ID, send only a generic message
	if status >= http.StatusInternalServerError {
		return erors.Internal(ctx, errors.Join(errs...))
	}
	// Step 2: body validation failures
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
				rctx := erors.WithRequestID(ctx.Context(), ctx.Header(erors.RequestIDHeader))
				se := newError(rctx, status, msg, errs...)
				// internal errors also carry their request ID in the X-Request-Id response header
				if ae, ok := se.(*erors.AuthError); ok && ae.RequestID != "" {
					ctx.SetHeader(erors.RequestIDHeader, ae.RequestID)
				}
				return se
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
	return &goauthAPI{API: api, reg: &opRegistry{routes: map[string]string{}, opIDs: map[string]string{}}}
}

type goauthAPI struct {
	huma.API
	reg *opRegistry
}

func (a *goauthAPI) Adapter() huma.Adapter {
	return markingAdapter{Adapter: a.API.Adapter(), reg: a.reg}
}

// opRegistry remembers every method+path and operation ID registered through one WrapAPI API, so two
// plugins (or a plugin and core) that register the same route are reported at startup instead of one
// silently shadowing the other (or the router panicking).
type opRegistry struct {
	mu     sync.Mutex
	routes map[string]string // "POST /api/auth/sign-in/email" → operation ID
	opIDs  map[string]string // operation ID → "POST /api/auth/sign-in/email"
	errs   []error
}

// claim records op; it returns false (and records an error) when the route or operation ID is taken.
func (r *opRegistry) claim(op *huma.Operation) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Step 1: the route key ignores path parameter names ({id} and {userId} collide in every router)
	route := op.Method + " " + normalizeRoutePath(op.Path)
	if prev, taken := r.routes[route]; taken {
		r.errs = append(r.errs, fmt.Errorf("route %s %s is registered twice (operations %q and %q)", op.Method, op.Path, prev, op.OperationID))
		return false
	}
	// Step 2: operation IDs must be unique in the OpenAPI document
	if op.OperationID != "" {
		if prev, taken := r.opIDs[op.OperationID]; taken {
			r.errs = append(r.errs, fmt.Errorf("operation ID %q is used by %s and %s %s", op.OperationID, prev, op.Method, op.Path))
			return false
		}
		r.opIDs[op.OperationID] = op.Method + " " + op.Path
	}
	r.routes[route] = op.OperationID
	return true
}

// normalizeRoutePath replaces every {param} with {} so routes that differ only in parameter names match.
func normalizeRoutePath(p string) string {
	var b strings.Builder
	depth := 0
	for _, c := range p {
		switch {
		case c == '{':
			depth++
			if depth == 1 {
				b.WriteString("{}")
			}
		case c == '}' && depth > 0:
			depth--
		case depth == 0:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// RegistrationError returns the duplicate routes / operation IDs registered through api (a WrapAPI API),
// joined into one error, or nil.
func RegistrationError(api huma.API) error {
	a, ok := api.(*goauthAPI)
	if !ok || a.reg == nil {
		return nil
	}
	a.reg.mu.Lock()
	defer a.reg.mu.Unlock()
	return errors.Join(a.reg.errs...)
}

// Transform skips the host's response transformers for operations marked with RawBodyMetaKey.
func (a *goauthAPI) Transform(ctx huma.Context, status string, v any) (any, error) {
	if op := ctx.Operation(); op != nil && op.Metadata[RawBodyMetaKey] == true {
		return v, nil
	}
	return a.API.Transform(ctx, status, v)
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
	reg *opRegistry
}

func (m markingAdapter) Handle(op *huma.Operation, handler func(ctx huma.Context)) {
	// a duplicate is reported by RegistrationError and not mounted, so the router does not panic
	if m.reg != nil && !m.reg.claim(op) {
		return
	}
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
