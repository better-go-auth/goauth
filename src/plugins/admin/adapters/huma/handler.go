package humaadmin

import (
	"context"
	"strings"

	autherr "github.com/better-go-auth/goauth/src/common/error"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/models/enums"
	"github.com/better-go-auth/goauth/src/plugins"
	adminmodels "github.com/better-go-auth/goauth/src/plugins/admin/config"
	"github.com/better-go-auth/goauth/src/plugins/admin/repository"
	adminsvc "github.com/better-go-auth/goauth/src/plugins/admin/services"
	"github.com/birukbelay/gocmn/src/server/middleware"
)

// AdminHandler holds admin-domain services and embeds AuthHandler for authentication.
type AdminHandler struct {
	Admin      adminsvc.IAdminService
	Config     adminmodels.AdminConfig
	Cfg        config.AuthConfig
	AdminRepo  repository.IAdminRepo
	MiddleWare *middleware.AuthMiddleware
	authFn     plugins.AuthenticateFunc
}

// NewAdminHandler creates a new AdminHandler.
func NewAdminHandler(admin adminsvc.IAdminService, cfg adminmodels.AdminConfig, mdlware *middleware.AuthMiddleware, authFn ...plugins.AuthenticateFunc) *AdminHandler {
	if len(cfg.AdminRoles) == 0 {
		cfg.AdminRoles = []enums.Role{enums.Admin}
	}
	var af plugins.AuthenticateFunc
	if len(authFn) > 0 {
		af = authFn[0]
	}
	return &AdminHandler{
		Admin:      admin,
		Config:     cfg,
		MiddleWare: mdlware,
		authFn:     af,
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

// Authenticate delegates authentication to the core authenticate function.
func (h *AdminHandler) Authenticate(ctx context.Context, auth humatypes.AuthHeaders) (*dtos.SessionResponse, error) {
	if h.authFn != nil {
		return h.authFn(ctx, auth)
	}
	return nil, autherr.ErrUnauthorized
}

