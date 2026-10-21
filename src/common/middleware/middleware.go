package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/better-go-auth/goauth/src/common/consts"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/models/enums"
	"github.com/better-go-auth/goauth/src/providers/token"
	"github.com/danielgtaylor/huma/v2"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

//============================ Functions Used By Middlewares ================================|
//
//========================================================================================|

// SessionClaimsResolver turns a better-auth session token (opaque bearer token or the signed session cookie)
// into claims, so cookie and bearer clients pass the same middleware as legacy JWT clients.
type SessionClaimsResolver interface {
	ClaimsFromSession(ctx context.Context, bearer, cookieHeader string) (*token.CustomClaims, error)
}

type AuthMiddleware struct {
	verifier   TokenVerifier
	revocation RevocationStore       // Optional
	roles      DynamicRoleResolver   // Optional
	sessions   SessionClaimsResolver // Optional
}

func NewAuthMiddleware(verifier TokenVerifier, revocation RevocationStore, roles DynamicRoleResolver) (*AuthMiddleware, error) {
	if verifier == nil {
		return nil, errors.New("verifier is nil")
	}
	return &AuthMiddleware{
		verifier:   verifier,
		revocation: revocation,
		roles:      roles,
	}, nil
}

// WithSessions enables session-token authentication next to access JWTs.
func (m *AuthMiddleware) WithSessions(r SessionClaimsResolver) { m.sessions = r }

func looksLikeJWT(tok string) bool { return strings.Count(tok, ".") == 2 }

func writeAuthError(ctx huma.Context, err *autherr.AuthError) {
	if err == nil {
		err = autherr.ErrUnauthorized
	}
	ctx.SetStatus(err.StatusCode)
	ctx.SetHeader("Content-Type", "application/json")
	_ = json.NewEncoder(ctx.BodyWriter()).Encode(err)
}

func claimsFromCtx(ctx huma.Context) (token.CustomClaims, bool) {
	v := ctx.Context().Value(consts.CtxClaims.Str())
	switch c := v.(type) {
	case token.CustomClaims:
		return c, true
	case *token.CustomClaims:
		if c != nil {
			return *c, true
		}
	}
	return token.CustomClaims{}, false
}

// type ICoreMiddleWareFunc interface {
// 	TokenVerifier
// 	RevocationStore
// }

//============================ Actual Middlewares ================================|
//
//========================================================================================|

type IAuthMiddleware interface {
	Trace(operationID string) func(huma.Context, func(huma.Context))
	Authenticate() func(huma.Context, func(huma.Context))
	Authorize(operationID consts.OperationId, allowedRoles []string) func(huma.Context, func(huma.Context))
}

// Authenticate Middleware (Handles Token Verification + Revocation Check).
// It accepts a legacy access JWT, or, when WithSessions is set, a session token as bearer or cookie.
func (m *AuthMiddleware) Authenticate() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		bearer := ""
		if parts := strings.Split(ctx.Header("Authorization"), " "); len(parts) == 2 && parts[1] != "undefined" && parts[1] != "null" {
			bearer = parts[1]
		}
		var claims token.CustomClaims
		switch {
		// if we have a n authorization token and it is a jwt token verify it with the verifier
		case bearer != "" && looksLikeJWT(bearer):
			c, err := m.verifier.VerifyToken(bearer)
			if err != nil {
				writeAuthError(ctx, autherr.ErrUnauthorized)
				return
			}
			// Revocation Check
			if m.revocation != nil && c.SessionID != "" {
				revoked, _ := m.revocation.IsRevoked(ctx.Context(), c.SessionID)
				if revoked {
					writeAuthError(ctx, autherr.ErrUnauthorized)
					return
				}
			}
			claims = c
		case m.sessions != nil && (bearer != "" || ctx.Header("Cookie") != ""):
			// the session lookup itself is the revocation check
			c, err := m.sessions.ClaimsFromSession(ctx.Context(), bearer, ctx.Header("Cookie"))
			if err != nil || c == nil {
				writeAuthError(ctx, autherr.ErrUnauthorized)
				return
			}
			claims = *c
		default:
			writeAuthError(ctx, autherr.ErrUnauthorized)
			return
		}
		ctx = huma.WithValue(ctx, consts.CtxClaims.Str(), claims)
		ctx = huma.WithValue(ctx, consts.CTXCompany_ID.Str(), claims.ActiveOrgId)
		ctx = huma.WithValue(ctx, consts.CTXUser_ID.Str(), claims.UserID)
		next(ctx)
	}
}

// Authorize Middleware (Static claims check OR Dynamic DB check)
// Missing claims -> 401 UNAUTHORIZED, insufficient role -> 403 FORBIDDEN.
func (m *AuthMiddleware) Authorize(operationID consts.OperationId, allowedRoles []string) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		if len(allowedRoles) == 0 {
			next(ctx)
			return
		}
		claims, ok := claimsFromCtx(ctx)
		if !ok {
			writeAuthError(ctx, autherr.ErrUnauthorized)
			return
		}

		// If dynamic DB role checking is enabled:
		if m.roles != nil {
			allowed, err := m.roles.HasPermission(ctx.Context(), claims.ActiveOrgId, claims.UserID, operationID.Str())
			if err != nil || !allowed {
				writeAuthError(ctx, autherr.ErrForbidden)
				return
			}
			next(ctx)
			return
		}
		// Fallback to static JWT Claims Role check:
		if !enums.HasRole(claims.Role, allowedRoles...) {
			writeAuthError(ctx, autherr.ErrForbidden)
			return
		}
		next(ctx)
	}
}

// Trace Middleware adds telemetry span attributes
func (m *AuthMiddleware) Trace(operationID string) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		span := trace.SpanFromContext(ctx.Context())
		if span != nil && span.IsRecording() && operationID != "" {
			span.SetAttributes(attribute.String("http.operation_id", operationID))
		}
		next(ctx)
	}
}
