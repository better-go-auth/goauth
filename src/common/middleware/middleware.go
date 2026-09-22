package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/better-go-auth/goauth/src/common/consts"
	"github.com/better-go-auth/goauth/src/common/util"
	"github.com/better-go-auth/goauth/src/providers/token"
	jwttoken "github.com/better-go-auth/goauth/src/providers/token/jwt-token"
	"github.com/danielgtaylor/huma/v2"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

//============================ Functions Used By Middlewares ================================|
//
//========================================================================================|

// TokenVerifier handles cryptographic token verification
type TokenVerifier interface {
	VerifyToken(tokenStr string) (token.CustomClaims, error)
}

// RevocationStore checks if a session or token has been invalidated
type RevocationStore interface {
	IsRevoked(ctx context.Context, sessionID string) (bool, error)
	IsTokenBlacklisted(ctx context.Context, tokenID string) (bool, error)
}

// DynamicRoleResolver checks database/cache for up-to-date roles & permissions
// Dynamic Resolver should exist only on the dynamic role plugin
type DynamicRoleResolver interface {
	GetUserRoles(ctx context.Context, companyID, userID string) ([]string, error)
	HasPermission(ctx context.Context, companyID, userID string, operationID string) (bool, error)
}

type AuthMiddleware struct {
	verifier   TokenVerifier
	revocation RevocationStore     // Optional
	roles      DynamicRoleResolver // Optional
}

func NewAuthMiddleware(verifier TokenVerifier, revocation RevocationStore, roles DynamicRoleResolver) *AuthMiddleware {
	return &AuthMiddleware{
		verifier:   verifier,
		revocation: revocation,
		roles:      roles,
	}
}

type ICoreMiddleWareFunc interface {
	TokenVerifier
	RevocationStore
}

//============================ Actual Middlewares ================================|
//
//========================================================================================|

type IOrgMiddleware interface {
	AuthorizeOrg(operationID consts.OperationId, allowedRoles []string) func(huma.Context, func(huma.Context))
}

type IAuthMiddleware interface {
	Trace(operationID string) func(huma.Context, func(huma.Context))
	Authenticate() func(huma.Context, func(huma.Context))
	Authorize(operationID consts.OperationId, allowedRoles []string) func(huma.Context, func(huma.Context))
}

type JWTTokenVerifier struct {
	accessSecret string
}

func NewJWTTokenVerifier(accessSecret string) *JWTTokenVerifier {
	return &JWTTokenVerifier{accessSecret: accessSecret}
}

func (v *JWTTokenVerifier) VerifyToken(tokenStr string) (token.CustomClaims, error) {
	claims, err := jwttoken.ValidateToken(tokenStr, v.accessSecret)
	if err != nil || claims == nil {
		return token.CustomClaims{}, fmt.Errorf("invalid token: %w", err)
	}
	return *claims, nil
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

// Authenticate Middleware (Handles Token Verification + Revocation Check)
func (m *AuthMiddleware) Authenticate() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		authHeader := ctx.Header("Authorization")
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[1] == "" || parts[1] == "undefined" || parts[1] == "null" {
			ctx.SetStatus(http.StatusForbidden)
			_, _ = ctx.BodyWriter().Write([]byte("Token Not Valid"))
			return
		}
		claims, err := m.verifier.VerifyToken(parts[1])
		if err != nil {
			ctx.SetStatus(http.StatusForbidden)
			_, _ = ctx.BodyWriter().Write([]byte("Token Not Valid"))
			return
		}
		// Revocation Check
		if m.revocation != nil && claims.SessionID != "" {
			revoked, _ := m.revocation.IsRevoked(ctx.Context(), claims.SessionID)
			if revoked {
				ctx.SetStatus(http.StatusUnauthorized)
				_, _ = ctx.BodyWriter().Write([]byte("Session Revoked"))
				return
			}
		}
		ctx = huma.WithValue(ctx, consts.CtxClaims.Str(), claims)
		ctx = huma.WithValue(ctx, consts.CTXCompany_ID.Str(), claims.ActiveOrgId)
		ctx = huma.WithValue(ctx, consts.CTXUser_ID.Str(), claims.UserID)
		next(ctx)
	}
}

// Authorize Middleware (Static claims check OR Dynamic DB check)
func (m *AuthMiddleware) Authorize(operationID consts.OperationId, allowedRoles []string) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		if len(allowedRoles) == 0 {
			next(ctx)
			return
		}
		claimsVal := ctx.Context().Value(consts.CtxClaims.Str())
		var claims token.CustomClaims
		switch c := claimsVal.(type) {
		case token.CustomClaims:
			claims = c
		case *token.CustomClaims:
			if c != nil {
				claims = *c
			}
		default:
			ctx.SetStatus(http.StatusUnauthorized)
			_, _ = ctx.BodyWriter().Write([]byte("Not Authorized"))
			return
		}

		// If dynamic DB role checking is enabled:
		if m.roles != nil {
			allowed, err := m.roles.HasPermission(ctx.Context(), claims.ActiveOrgId, claims.UserID, operationID.Str())
			if err != nil || !allowed {
				ctx.SetStatus(http.StatusUnauthorized)
				_, _ = ctx.BodyWriter().Write([]byte("Not Authorized"))
				return
			}
			next(ctx)
			return
		}
		// Fallback to static JWT Claims Role check:
		if !util.ElementExists(claims.Role, allowedRoles...) {
			ctx.SetStatus(http.StatusUnauthorized)
			_, _ = ctx.BodyWriter().Write([]byte("Not Authorized"))
			return
		}
		next(ctx)
	}
}

// AuthorizeOrg Middleware
func (m *AuthMiddleware) AuthorizeOrg(operationID consts.OperationId, allowedRoles []string) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		claimsVal := ctx.Context().Value(consts.CtxClaims.Str())
		var claims token.CustomClaims
		switch c := claimsVal.(type) {
		case token.CustomClaims:
			claims = c
		case *token.CustomClaims:
			if c != nil {
				claims = *c
			}
		default:
			ctx.SetStatus(http.StatusUnauthorized)
			_, _ = ctx.BodyWriter().Write([]byte("Not Authorized"))
			return
		}

		if claims.ActiveOrgId == "" || claims.ActiveOrgRole == "" || claims.UserID == "" {
			ctx.SetStatus(http.StatusUnauthorized)
			_, _ = ctx.BodyWriter().Write([]byte("Not Authorized"))
			return
		}
		if len(allowedRoles) == 0 {
			next(ctx)
			return
		}
		if !util.ElementExists(claims.ActiveOrgRole, allowedRoles...) {
			ctx.SetStatus(http.StatusUnauthorized)
			_, _ = ctx.BodyWriter().Write([]byte("Not Authorized"))
			return
		}
		next(ctx)
	}
}
