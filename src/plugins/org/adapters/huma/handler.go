package humaorg

import (
	"context"
	"net/http"
	"strings"

	"github.com/better-go-auth/goauth/src/providers/authenticator"
	"github.com/better-go-auth/goauth/src/common/middleware"
	"github.com/danielgtaylor/huma/v2"

	autherr "github.com/better-go-auth/goauth/src/common/errors"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
	orgsvc "github.com/better-go-auth/goauth/src/plugins/org/services"
)

// OrgHandler holds org-domain services and embeds AuthHandler for authentication.
type OrgHandler struct {
	Org        orgsvc.IOrgService
	Cfg        config.AuthConfig
	MiddleWare *middleware.AuthMiddleware
	authFn     authenticator.AuthenticateFunc
}

// NewOrgHandler creates a new OrgHandler.
func NewOrgHandler(org orgsvc.IOrgService, mdlware *middleware.AuthMiddleware, authFn ...authenticator.AuthenticateFunc) *OrgHandler {
	var af authenticator.AuthenticateFunc
	if len(authFn) > 0 {
		af = authFn[0]
	}
	return &OrgHandler{Org: org, MiddleWare: mdlware, authFn: af}
}

// RequireOrgRoles authenticates the user and checks they hold one of the given
// roles in their active organization. Returns the session, active org ID, and any error.
func (h *OrgHandler) RequireOrgRoles(ctx context.Context, auth humatypes.AuthHeaders, allowedOrgRoles ...string) (string, error) {
	sessionResp, err := h.Authenticate(ctx, auth)
	if err != nil {
		return "", err
	}
	if sessionResp.Session.ActiveOrganizationID == nil {
		return "", huma.NewError(http.StatusForbidden, "No active organization set")
	}
	orgID := *sessionResp.Session.ActiveOrganizationID
	member, err := h.Org.GetMember(ctx, orgID, sessionResp.User.ID)
	if err != nil || member == nil {
		return "", autherr.ErrForbidden
	}
	for _, allowed := range allowedOrgRoles {
		if strings.EqualFold(string(member.Role), allowed) {
			return orgID, nil
		}
	}
	return "", autherr.ErrForbidden
}

// defaultPagi returns sensible default pagination for org list endpoints.
func defaultPagi() models.Pagination {
	return models.Pagination{Limit: 50, Offset: 0, SortBy: "created_at", SortDir: "desc"}
}

// Authenticate delegates authentication to the core authenticate function.
// It first checks if the request was already authenticated into context by middleware.
func (h *OrgHandler) Authenticate(ctx context.Context, auth humatypes.AuthHeaders) (*dtos.SessionResponse, error) {
	if sess, ok := authenticator.SessionFromContext(ctx); ok && sess != nil {
		return sess, nil
	}
	if h.authFn != nil {
		return h.authFn(ctx, auth)
	}
	return nil, autherr.ErrUnauthorized
}
