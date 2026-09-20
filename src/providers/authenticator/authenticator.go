package authenticator

import (
	"context"
	"strings"
	"time"

	autherr "github.com/better-go-auth/goauth/src/common/error"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/providers/token"
	jwttoken "github.com/better-go-auth/goauth/src/providers/token/jwt-token"
	"github.com/birukbelay/gocmn/src/consts"
	"gorm.io/gorm"
)

// AuthenticateFunc authenticates an incoming request and returns the active SessionResponse.
type AuthenticateFunc func(ctx context.Context, auth humatypes.AuthHeaders) (*dtos.SessionResponse, error)

// SessionLookupRepo defines the data access methods required by Authenticator for fallback lookups.
type SessionLookupRepo interface {
	GetSessionByToken(ctx context.Context, token string) (*models.Session, error)
	GetUserByID(ctx context.Context, id string) (*models.User, error)
}

// gormSessionLookup wraps a *gorm.DB to satisfy SessionLookupRepo for backward compatibility.
type gormSessionLookup struct {
	db *gorm.DB
}

func (g *gormSessionLookup) GetSessionByToken(ctx context.Context, token string) (*models.Session, error) {
	var sess models.Session
	err := g.db.WithContext(ctx).Where("session_id = ? OR hashed_token = ?", token, token).First(&sess).Error
	return &sess, err
}

func (g *gormSessionLookup) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	var user models.User
	err := g.db.WithContext(ctx).Where("id = ?", id).First(&user).Error
	return &user, err
}

// NewDefaultAuthenticator returns an AuthenticateFunc provided by the core to plugins.
// It handles:
// 1. Context claims (when Huma middleware has already authenticated the request)
// 2. Token extraction from Bearer Authorization header or session cookies
// 3. JWT verification against the session access secret
// 4. Database session and user lookup fallback via SessionLookupRepo
func NewDefaultAuthenticator(accessSecret string, lookup SessionLookupRepo) AuthenticateFunc {
	return func(ctx context.Context, auth humatypes.AuthHeaders) (*dtos.SessionResponse, error) {
		// 1. Check if claims already exist in ctx (set by middleware)
		if sesResp, valid := SessionFromContext(ctx); valid {
			return sesResp, nil
		}

		// 2. Extract token from Authorization header or Cookie
		token := auth.Authorization
		if strings.HasPrefix(strings.ToLower(token), "bearer ") {
			token = strings.TrimSpace(token[7:])
		}
		// if the authorization token is empty, try to extract from cookie
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
			claims, err := jwttoken.ValidateToken(token, accessSecret)
			if err == nil && claims.UserID != "" {
				return sessionResponseFromClaims(claims, token)
			}
		}

		// 4. Fallback: lookup session in database by token (for opaque or database sessions)
		if lookup != nil {
			sess, err := lookup.GetSessionByToken(ctx, token)
			if err == nil && sess != nil && sess.UserID != "" {
				if sess.ExpiresAt.Before(time.Now().UTC()) {
					return nil, autherr.ErrUnauthorized
				}
				if sess.Blacklisted != nil && *sess.Blacklisted {
					return nil, autherr.ErrUnauthorized
				}
				if sess.RevokedAt != nil {
					return nil, autherr.ErrUnauthorized
				}

				user, err := lookup.GetUserByID(ctx, sess.UserID)
				if err == nil && user != nil {
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

// NewDefaultAuthenticatorWithDB is a backward-compatible wrapper that takes a *gorm.DB.
func NewDefaultAuthenticatorWithDB(accessSecret string, db *gorm.DB) AuthenticateFunc {
	if db == nil {
		return NewDefaultAuthenticator(accessSecret, nil)
	}
	return NewDefaultAuthenticator(accessSecret, &gormSessionLookup{db: db})
}

// SessionFromContext extracts the authenticated SessionResponse from context if claims were set by middleware.
func SessionFromContext(ctx context.Context) (session *dtos.SessionResponse, valid bool) {
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
	return sess.User, true
}

func sessionResponseFromClaims(claims *token.CustomClaims, token string) (*dtos.SessionResponse, error) {
	var activeOrgID *string
	var activeOrgRole *string

	orgID := claims.ActiveOrgId
	if orgID != "" {
		activeOrgID = &orgID
	}
	if claims.ActiveOrgRole != "" {
		activeOrgRole = &claims.ActiveOrgRole
	}
	return &dtos.SessionResponse{
		User: &dtos.UserResponse{
			ID:   claims.UserID,
			Role: claims.Role,
		},
		Session: &dtos.SessionData{
			ID:                   claims.SessionID,
			UserID:               claims.UserID,
			Token:                token,
			ActiveOrganizationID: activeOrgID,
			ActiveOrgRole:        activeOrgRole,
			Role:                 claims.Role,
		},
	}, nil
}
