package middleware

import (
	"context"

	"github.com/better-go-auth/goauth/src/common/consts"
	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/common/util"
	"github.com/danielgtaylor/huma/v2"
)

type IOrgMiddleware interface {
	AuthorizeOrg(operationID consts.OperationId, allowedRoles []string) func(huma.Context, func(huma.Context))
}

// DynamicRoleResolver checks database/cache for up-to-date roles & permissions
// Dynamic Resolver should exist only on the dynamic role plugin
type DynamicRoleResolver interface {
	GetUserRoles(ctx context.Context, companyID, userID string) ([]string, error)
	HasPermission(ctx context.Context, companyID, userID string, operationID string) (bool, error)
}

// AuthorizeOrg Middleware
func (m *AuthMiddleware) AuthorizeOrg(operationID consts.OperationId, allowedRoles []string) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		claims, ok := claimsFromCtx(ctx)
		if !ok {
			writeAuthError(ctx, autherr.ErrUnauthorized)
			return
		}

		if claims.ActiveOrgId == "" || claims.ActiveOrgRole == "" || claims.UserID == "" {
			writeAuthError(ctx, autherr.ErrForbidden)
			return
		}
		if len(allowedRoles) == 0 {
			next(ctx)
			return
		}
		if !util.ElementExists(claims.ActiveOrgRole, allowedRoles...) {
			writeAuthError(ctx, autherr.ErrForbidden)
			return
		}
		next(ctx)
	}
}
