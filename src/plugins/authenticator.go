package plugins

import (
	"context"
	"strings"
	"time"

	autherr "github.com/better-go-auth/goauth/src/common/error"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/birukbelay/gocmn/src/consts"
	"github.com/birukbelay/gocmn/src/crypto"
	"gorm.io/gorm"
)

// AuthenticateFunc authenticates an incoming request and returns the active SessionResponse.
type AuthenticateFunc func(ctx context.Context, auth humatypes.AuthHeaders) (*dtos.SessionResponse, error)

// NewDefaultAuthenticator returns an AuthenticateFunc provided by the core to plugins.
// It handles:
// 1. Context claims (when Huma middleware has already authenticated the request)
// 2. Token extraction from Bearer Authorization header or session cookies
// 3. JWT verification against the session access secret
// 4. Database session and user lookup fallback
func NewDefaultAuthenticator(accessSecret string, db *gorm.DB) AuthenticateFunc {
	return func(ctx context.Context, auth humatypes.AuthHeaders) (*dtos.SessionResponse, error) {
		// 1. Check if claims already exist in ctx (set by middleware)
		if v, ok := ctx.Value(consts.CtxClaims.Str()).(crypto.CustomClaims); ok && v.UserId != "" {
			return sessionResponseFromClaims(&v, "")
		}
		if vp, ok := ctx.Value(consts.CtxClaims.Str()).(*crypto.CustomClaims); ok && vp != nil && vp.UserId != "" {
			return sessionResponseFromClaims(vp, "")
		}

		// 2. Extract token from Authorization header or Cookie
		token := auth.Authorization
		if strings.HasPrefix(strings.ToLower(token), "bearer ") {
			token = strings.TrimSpace(token[7:])
		}
		if token == "" && auth.Cookie != "" {
			parts := strings.Split(auth.Cookie, ";")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if strings.HasPrefix(part, "better-auth.session_token=") {
					token = strings.TrimPrefix(part, "better-auth.session_token=")
					break
				}
			}
		}

		if token == "" {
			return nil, autherr.ErrUnauthorized
		}

		// 3. Verify JWT
		if accessSecret != "" {
			claims, ok, err := crypto.Valid(token, accessSecret)
			if err == nil && ok && claims.UserId != "" {
				return sessionResponseFromClaims(&claims, token)
			}
		}

		// 4. Fallback: lookup session in database by token (for opaque or database sessions)
		if db != nil {
			var sess models.Session
			err := db.WithContext(ctx).Where("session_id = ? OR hashed_token = ?", token, token).First(&sess).Error
			if err == nil && sess.UserID != "" {
				if sess.ExpiresAt.Before(time.Now().UTC()) {
					return nil, autherr.ErrUnauthorized
				}
				if sess.Blacklisted != nil && *sess.Blacklisted {
					return nil, autherr.ErrUnauthorized
				}
				if sess.RevokedAt != nil {
					return nil, autherr.ErrUnauthorized
				}

				var user models.User
				if err := db.WithContext(ctx).Where("id = ?", sess.UserID).First(&user).Error; err == nil {
					var email string
					if user.Email != nil {
						email = *user.Email
					}
					var activeOrgRole *string
					if sess.OrgRoleID != nil {
						activeOrgRole = sess.OrgRoleID
					}
					return &dtos.SessionResponse{
						User: &dtos.UserResponse{
							ID:            user.ID,
							Email:         email,
							Role:          string(user.Role),
							Banned:        user.Banned,
							BanReason:     user.BanReason,
							EmailVerified: user.EmailVerified,
						},
						Session: &dtos.SessionData{
							ID:                   sess.ID,
							UserID:               sess.UserID,
							Token:                token,
							ActiveOrganizationID: sess.ActiveOrgID,
							ActiveOrgRole:        activeOrgRole,
						},
					}, nil
				}
			}
		}

		return nil, autherr.ErrUnauthorized
	}
}

func sessionResponseFromClaims(claims *crypto.CustomClaims, token string) (*dtos.SessionResponse, error) {
	var activeOrgID *string
	var activeOrgRole *string
	if claims.CompanyId != "" {
		activeOrgID = &claims.CompanyId
	}
	if claims.OrgRole != "" {
		activeOrgRole = &claims.OrgRole
	}
	return &dtos.SessionResponse{
		User: &dtos.UserResponse{
			ID:   claims.UserId,
			Role: claims.Role,
		},
		Session: &dtos.SessionData{
			ID:                   claims.SessionId,
			UserID:               claims.UserId,
			Token:                token,
			ActiveOrganizationID: activeOrgID,
			ActiveOrgRole:        activeOrgRole,
		},
	}, nil
}
