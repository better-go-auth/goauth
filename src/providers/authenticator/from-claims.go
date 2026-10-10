package authenticator

import (
	"context"

	"github.com/better-go-auth/goauth/src/common/consts"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/providers/token"
)

// SessionFromContext extracts the authenticated SessionWithUser from context if claims were set by middleware.
func SessionFromContext(ctx context.Context) (session *dtos.SessionWithUser, valid bool) {
	if v, ok := ctx.Value(consts.CtxClaims.Str()).(token.CustomClaims); ok && v.UserID != "" {
		sess, err := sessionResponseFromClaims(&v, "")
		return sess, err == nil
	}
	if vp, ok := ctx.Value(consts.CtxClaims.Str()).(*token.CustomClaims); ok && vp != nil && vp.UserID != "" {
		sess, err := sessionResponseFromClaims(vp, "")
		return sess, err == nil
	}
	return nil, false
}

// UserFromContext extracts the authenticated UserResponse from context if present.
func UserFromContext(ctx context.Context) (*dtos.UserResponse, bool) {
	sess, ok := SessionFromContext(ctx)
	if !ok || sess == nil {
		return nil, false
	}
	return &sess.User, true
}

func sessionResponseFromClaims(claims *token.CustomClaims, token string) (*dtos.SessionWithUser, error) {
	var activeOrgID *string
	var activeOrgRole *string

	orgID := claims.ActiveOrgId
	if orgID != "" {
		activeOrgID = &orgID
	}
	if claims.ActiveOrgRole != "" {
		activeOrgRole = &claims.ActiveOrgRole
	}
	return &dtos.SessionWithUser{
		User: dtos.UserResponse{
			ID:   claims.UserID,
			Role: claims.Role,
		},
		Session: dtos.SessionData{
			ID:                     claims.SessionID,
			UserID:                 claims.UserID,
			Token:                  token,
			ActiveOrganizationID:   activeOrgID,
			ActiveOrganizationRole: activeOrgRole,
		},
	}, nil
}
