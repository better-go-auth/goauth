package humaadapter

import (
	"context"
	"encoding/json"

	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	"github.com/danielgtaylor/huma/v2"
)

type ctxKey struct{}

// WithSession stores the resolved session in ctx.
func WithSession(ctx context.Context, sw *dtos.SessionWithUser) context.Context {
	return context.WithValue(ctx, ctxKey{}, sw)
}

// FromContext returns the session put in ctx by a Resolver middleware.
func FromContext(ctx context.Context) (*dtos.SessionWithUser, bool) {
	sw, ok := ctx.Value(ctxKey{}).(*dtos.SessionWithUser)
	return sw, ok && sw != nil
}

// Resolver turns the signed session cookie into a session for Huma operations.
type Resolver struct {
	mgr     *sessionsvc.Manager
	cookies *cookies.Manager
}

func NewResolver(mgr *sessionsvc.Manager, cm *cookies.Manager) *Resolver {
	return &Resolver{mgr: mgr, cookies: cm}
}

// Resolve returns the session for a Cookie header, or nil when there is none.
func (r *Resolver) Resolve(ctx context.Context, cookieHeader string) (*dtos.SessionWithUser, error) {
	tok, ok := r.cookies.SessionToken(cookieHeader)
	if !ok {
		return nil, nil
	}
	return r.mgr.Get(ctx, tok)
}

// Optional attaches the session to the context when present.
func (r *Resolver) Optional() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		sw, err := r.Resolve(ctx.Context(), ctx.Header("Cookie"))
		if err != nil {
			writeError(ctx, autherr.ErrFailedToGetSession)
			return
		}
		if sw != nil {
			ctx = huma.WithContext(ctx, WithSession(ctx.Context(), sw))
		}
		next(ctx)
	}
}

// Require rejects requests without a valid session with 401 UNAUTHORIZED.
func (r *Resolver) Require() func(huma.Context, func(huma.Context)) {
	return r.require(false)
}

// RequireFresh additionally rejects sessions older than FreshAge with 403 SESSION_NOT_FRESH.
func (r *Resolver) RequireFresh() func(huma.Context, func(huma.Context)) {
	return r.require(true)
}

func (r *Resolver) require(fresh bool) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		sw, err := r.Resolve(ctx.Context(), ctx.Header("Cookie"))
		if err != nil {
			writeError(ctx, autherr.ErrFailedToGetSession)
			return
		}
		if sw == nil {
			writeError(ctx, autherr.ErrUnauthorized)
			return
		}
		if fresh && !r.mgr.IsFresh(sw) {
			writeError(ctx, autherr.ErrSessionNotFresh)
			return
		}
		next(huma.WithContext(ctx, WithSession(ctx.Context(), sw)))
	}
}

func writeError(ctx huma.Context, e *autherr.AuthError) {
	ctx.SetHeader("Content-Type", "application/json")
	ctx.SetStatus(e.StatusCode)
	_ = json.NewEncoder(ctx.BodyWriter()).Encode(e)
}
