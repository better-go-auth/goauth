package humaadmin

import (
	"context"
	"strings"

	"github.com/better-go-auth/goauth/src/app/core/core_interfaces"
	autherr "github.com/better-go-auth/goauth/src/common/error"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/models/enums"
	adminmodels "github.com/better-go-auth/goauth/src/plugins/admin/models"
	"github.com/better-go-auth/goauth/src/plugins/admin/repository"
	adminsvc "github.com/better-go-auth/goauth/src/plugins/admin/services"
	"github.com/birukbelay/gocmn/src/consts"
	"github.com/birukbelay/gocmn/src/crypto"
)

// AdminHandler holds admin-domain services and embeds AuthHandler for authentication.
type AdminHandler struct {
	// *humaauth.AuthHandler
	Admin       adminsvc.IAdminService
	Config      adminmodels.AdminConfig
	Cfg         config.GoAuthOptions
	sessionServ core_interfaces.ISessionService
	AdminRepo   repository.IAdminRepo
	// JwtSecret   string
}

// NewAdminHandler creates a new AdminHandler.
func NewAdminHandler(admin adminsvc.IAdminService, cfg adminmodels.AdminConfig) *AdminHandler {
	if len(cfg.AdminRoles) == 0 {
		cfg.AdminRoles = []enums.Role{enums.Admin}
	}
	return &AdminHandler{
		// AuthHandler: auth,
		Admin:  admin,
		Config: cfg,
	}
}

// RequireAdmin authenticates the request and checks that the user has an authorized admin role.
func (h *AdminHandler) RequireAdmin(ctx context.Context, auth humatypes.AuthHeaders) (*dtos.SessionResponse, error) {
	sessionResp, err := h.Authenticate(ctx, auth)
	if err != nil {
		return nil, err
	}
	if sessionResp.User == nil {
		return nil, autherr.ErrUnauthorized
	}
	if sessionResp.User.Banned {
		return nil, autherr.ErrForbidden
	}

	for _, allowed := range h.Config.AdminRoles {
		if strings.EqualFold(sessionResp.User.Role, allowed.S()) {
			return sessionResp, nil
		}
	}
	return nil, autherr.ErrForbidden
}

// Authenticate authenticates a request using context claims, Bearer token, or session cookie.
func (h *AdminHandler) Authenticate(ctx context.Context, auth humatypes.AuthHeaders) (*dtos.SessionResponse, error) {
	// 1. Check if claims already exist in ctx (set by middleware)
	if v, ok := ctx.Value(consts.CtxClaims.Str()).(crypto.CustomClaims); ok && v.UserId != "" {
		return h.sessionResponseFromClaims(ctx, &v, "")
	}
	if vp, ok := ctx.Value(consts.CtxClaims.Str()).(*crypto.CustomClaims); ok && vp != nil && vp.UserId != "" {
		return h.sessionResponseFromClaims(ctx, vp, "")
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

	secret := h.Cfg.SessionConfig.AccessSecret
	// if secret == "" {

	// }
	if secret != "" {
		claims, ok, err := crypto.Valid(token, secret)
		if err == nil && ok && claims.UserId != "" {
			return h.sessionResponseFromClaims(ctx, &claims, token)
		}
	}

	// 3. Fallback: lookup session in database by token (e.g. for impersonation or opaque session tokens)
	if h.AdminRepo != nil {
		sess, err := h.AdminRepo.GetSessionByToken(ctx, token)
		if err == nil && sess != nil {
			user, err := h.AdminRepo.GetUserByID(ctx, sess.UserID)
			if err == nil && user != nil {
				var email string
				if user.Email != nil {
					email = *user.Email
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
						ID:             sess.ID,
						UserID:         sess.UserID,
						Token:          token,
						ImpersonatedBy: sess.ImpersonatedBy,
					},
				}, nil
			}
		}
	}

	return nil, autherr.ErrUnauthorized
}

func (h *AdminHandler) sessionResponseFromClaims(ctx context.Context, claims *crypto.CustomClaims, token string) (*dtos.SessionResponse, error) {
	if h.AdminRepo != nil {
		user, err := h.AdminRepo.GetUserByID(ctx, claims.UserId)
		if err == nil && user != nil {
			role := string(user.Role)
			if role == "" {
				role = claims.Role
			}
			banned := user.Banned
			var email string
			if user.Email != nil {
				email = *user.Email
			}
			return &dtos.SessionResponse{
				User: &dtos.UserResponse{
					ID:            user.ID,
					Email:         email,
					Role:          role,
					Banned:        banned,
					BanReason:     user.BanReason,
					EmailVerified: user.EmailVerified,
				},
				Session: &dtos.SessionData{
					ID:     claims.SessionId,
					UserID: claims.UserId,
					Token:  token,
				},
			}, nil
		}
	}

	return &dtos.SessionResponse{
		User: &dtos.UserResponse{
			ID:   claims.UserId,
			Role: claims.Role,
		},
		Session: &dtos.SessionData{
			ID:     claims.SessionId,
			UserID: claims.UserId,
			Token:  token,
		},
	}, nil
}
