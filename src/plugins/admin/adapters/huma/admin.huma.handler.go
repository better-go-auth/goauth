package humaadmin

import (
	"context"

	humaadapter "github.com/better-go-auth/goauth/src/app/adapters/huma"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/consts"
	"github.com/better-go-auth/goauth/src/common/middleware"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/models/enums"
	adminmodels "github.com/better-go-auth/goauth/src/plugins/admin/config"
	"github.com/better-go-auth/goauth/src/plugins/admin/repository"
	adminsvc "github.com/better-go-auth/goauth/src/plugins/admin/services"
	"github.com/better-go-auth/goauth/src/providers/access"
	"github.com/better-go-auth/goauth/src/providers/authenticator"
	"github.com/better-go-auth/goauth/src/providers/cookies"
)

// AdminHandler holds admin-domain services and embeds AuthHandler for authentication.
type AdminHandler struct {
	Admin      adminsvc.IAdminService
	Config     adminmodels.AdminConfig
	Cfg        config.AuthConfig
	AdminRepo  repository.IAdminRepo
	MiddleWare *middleware.AuthMiddleware
	authFn     authenticator.AuthenticateFunc
	Cookies    *cookies.Manager
}

// NewAdminHandler creates a new AdminHandler.
func NewAdminHandler(admin adminsvc.IAdminService, cfg adminmodels.AdminConfig, mdlware *middleware.AuthMiddleware, authFn ...authenticator.AuthenticateFunc) *AdminHandler {
	if len(cfg.AdminRoles) == 0 {
		cfg.AdminRoles = []enums.Role{enums.Admin}
	}
	var af authenticator.AuthenticateFunc
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
func (h *AdminHandler) RequireAdmin(ctx context.Context, auth humatypes.AuthHeaders) (*dtos.SessionWithUser, error) {
	sessionResp, err := h.Authenticate(ctx, auth)
	if err != nil {
		return nil, err
	}
	if sessionResp.User.ID == "" {
		return nil, autherr.ErrUnauthorized
	}
	if sessionResp.User.Banned {
		return nil, autherr.ErrForbidden
	}

	for _, allowed := range h.Config.AdminRoles {
		if enums.HasRole(sessionResp.User.Role, allowed.S()) {
			return sessionResp, nil
		}
	}
	return nil, autherr.ErrForbidden
}

// RequirePermission authenticates the request and checks the caller has the better-auth admin
// permission for the route (e.g. {"user": ["list"]}); denied is returned when they don't.
// Roles come from AdminConfig.EffectiveRoles: better-auth's default {admin, user} roles, the custom
// Roles, or (GoAuth.AdminRolesFullAccess) every AdminRoles entry mapped to the admin role.
func (h *AdminHandler) RequirePermission(ctx context.Context, auth humatypes.AuthHeaders, perm access.Request, denied *autherr.AuthError) (*dtos.SessionWithUser, error) {
	// Step 1: authenticate the caller
	sessionResp, err := h.Authenticate(ctx, auth)
	if err != nil {
		return nil, err
	}
	if sessionResp.User.ID == "" {
		return nil, autherr.ErrUnauthorized
	}
	// Step 2: banned users never reach admin routes
	if sessionResp.User.Banned {
		return nil, autherr.ErrForbidden
	}
	// Step 3: check the route permission against the caller's role(s) / adminUserIds
	if !h.Config.HasPermission(sessionResp.User.ID, sessionResp.User.Role, perm) {
		if denied == nil {
			denied = autherr.ErrForbidden
		}
		return nil, denied
	}
	return sessionResp, nil
}

// can reports whether the authenticated caller has perm (used for conditional sub-checks).
func (h *AdminHandler) can(session *dtos.SessionWithUser, perm access.Request) bool {
	return h.Config.HasPermission(session.User.ID, session.User.Role, perm)
}

// checkRolesExist rejects role values that are not configured when custom roles are set
// (better-auth: `opts.roles && !opts.roles[role]`).
func (h *AdminHandler) checkRolesExist(role string) error {
	if !h.Config.CustomRoles() {
		return nil
	}
	for _, r := range access.SplitRoles(role) {
		if _, ok := h.Config.Roles[r]; !ok {
			return adminmodels.ErrNotAllowedToSetNonExistentRole
		}
	}
	return nil
}

// RouteRoles returns, for the active configuration, the role names that pass op's permission
// check (AdminConfig.AdminRoles without custom roles, else the custom roles granting it).
// nil means any authenticated user (has-permission, stop-impersonating). Users listed in
// AdminUserIDs pass regardless of role.
func (h *AdminHandler) RouteRoles(op consts.OperationId) []string {
	perm, ok := RoutePermissions[op]
	if !ok || len(perm) == 0 {
		return nil
	}
	return h.Config.RolesGranting(perm)
}

// Authenticate delegates authentication to the core authenticate function.
// It first checks if the request was already authenticated into context by middleware.
func (h *AdminHandler) Authenticate(ctx context.Context, auth humatypes.AuthHeaders) (*dtos.SessionWithUser, error) {
	// TODO: use the plain session authenticator or the authFn based on the config
	// Step 1: a full session a middleware already resolved (it has the token and every user field)
	if sess, ok := humaadapter.FromContext(ctx); ok && sess != nil && sess.User.ID != "" {
		return sess, nil
	}
	// Step 2: resolve the full session from the request's cookie / bearer header. The claims-only
	// session below has no token (impersonation needs it for the admin_session cookie) and no
	// banned flag, so it is only the fallback.
	if h.authFn != nil {
		if sess, err := h.authFn(ctx, auth); err == nil && sess != nil {
			return sess, nil
		} else if _, ok := authenticator.SessionFromContext(ctx); !ok {
			return nil, err
		}
	}
	// Step 3: the claims a token middleware put in the context
	if sess, ok := authenticator.SessionFromContext(ctx); ok && sess != nil {
		return sess, nil
	}
	return nil, autherr.ErrUnauthorized
}
