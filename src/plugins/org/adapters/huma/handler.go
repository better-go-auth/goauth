package humaorg

import (
	"context"
	"net/http"
	"strings"

	"github.com/birukbelay/gocmn/src/consts"
	"github.com/birukbelay/gocmn/src/crypto"
	"github.com/danielgtaylor/huma/v2"

	autherr "github.com/better-go-auth/goauth/src/common/error"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
	orgsvc "github.com/better-go-auth/goauth/src/plugins/org/services"
)

// OrgHandler holds org-domain services and embeds AuthHandler for authentication.
type OrgHandler struct {
	// *humaauth.AuthHandler
	Org orgsvc.IOrgService
	Cfg config.AuthConfig
}

// NewOrgHandler creates a new OrgHandler.
func NewOrgHandler(org orgsvc.IOrgService) *OrgHandler {
	return &OrgHandler{Org: org}
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

// Authenticate authenticates a request using context claims, Bearer token, or session cookie.
func (h *OrgHandler) Authenticate(ctx context.Context, auth humatypes.AuthHeaders) (*dtos.SessionResponse, error) {
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

	return nil, autherr.ErrUnauthorized
}

func (h *OrgHandler) sessionResponseFromClaims(ctx context.Context, claims *crypto.CustomClaims, token string) (*dtos.SessionResponse, error) {
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
