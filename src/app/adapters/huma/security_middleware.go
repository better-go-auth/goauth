package humaadapter

import (
	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	"github.com/better-go-auth/goauth/src/providers/origin"
	"github.com/danielgtaylor/huma/v2"
)

// SecurityMiddleware returns a Huma API middleware that enforces AuthConfig.DisabledOps and
// AuthConfig.Security policies across all registered core, plugin, and application operations
// based on OperationID:
//   - DisabledOps: blocks disabled operations (including plugin routes) with 404 Not Found
//   - CheckOriginOnPluginMutations: Origin/Referer CSRF check on mutating cookie requests
//   - RequireFreshOps: rejects unauthenticated or stale (outside Session.FreshAge) sessions
func SecurityMiddleware(conf config.AuthConfig, mgr *sessionsvc.Manager, cm *cookies.Manager, origins *origin.Checker) func(ctx huma.Context, next func(huma.Context)) {
	disabledSet := config.OperationSet(conf.DisabledOps)
	freshSet := config.OperationSet(conf.Security.RequireFreshOps)
	checkOrigin := conf.Security.CheckOriginOnPluginMutations

	// Zero-overhead pass-through when no security policies are configured
	if !checkOrigin && len(disabledSet) == 0 && len(freshSet) == 0 {
		return func(ctx huma.Context, next func(huma.Context)) { next(ctx) }
	}

	return func(ctx huma.Context, next func(huma.Context)) {
		var opID string
		if op := ctx.Operation(); op != nil {
			opID = op.OperationID
		}

		// 0. Block disabled operations (including plugin routes that bypass core RegisterRoutes)
		if opID != "" && disabledSet[opID] {
			writeError(ctx, autherr.NotFoundErr("Not Found"))
			return
		}

		// 1. Optional global Origin/Referer CSRF check across mutating endpoints (including plugins)
		if checkOrigin {
			if err := OriginError(ctx, conf, origins, false); err != nil {
				writeError(ctx, err)
				return
			}
		}

		// 2. Enforce fresh login window (Session.FreshAge) for listed operations
		if opID != "" && mgr != nil && freshSet[opID] {
			sw := resolveContextOrCookieSession(ctx, mgr, cm)
			if sw == nil {
				writeError(ctx, autherr.ErrUnauthorized)
				return
			}
			if !mgr.IsFresh(sw) {
				writeError(ctx, autherr.ErrSessionNotFresh)
				return
			}
		}

		next(ctx)
	}
}

func resolveContextOrCookieSession(ctx huma.Context, mgr *sessionsvc.Manager, cm *cookies.Manager) *dtos.SessionWithUser {
	// 1. Prefer session already resolved by an upstream middleware (e.g. access-token)
	if sw, ok := FromContext(ctx.Context()); ok && sw != nil {
		return sw
	}
	// 2. Fall back to the HMAC-signed session cookie (including cookies injected by bearer plugin)
	if cm == nil || mgr == nil {
		return nil
	}
	cookieHeader := ctx.Header("Cookie")
	if cookieHeader == "" {
		return nil
	}
	cookieTok, ok := cm.SessionToken(cookieHeader)
	if !ok || cookieTok == "" {
		return nil
	}
	sw, err := mgr.Get(ctx.Context(), cookieTok)
	if err != nil {
		return nil
	}
	return sw
}

