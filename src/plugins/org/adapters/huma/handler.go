package humaorg

import (
	"context"
	"net/http"
	"strings"

	"github.com/better-go-auth/goauth/src/common/consts"
	"github.com/better-go-auth/goauth/src/common/middleware"
	"github.com/better-go-auth/goauth/src/providers/authenticator"

	autherr "github.com/better-go-auth/goauth/src/common/errors"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
	orgerrors "github.com/better-go-auth/goauth/src/plugins/org/org-errors"
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

// RequireOrgMember authenticates the caller and checks, against the member table, that they belong to
// orgID (the session's active organization when orgID is empty) with one of roles (any role when empty).
func (h *OrgHandler) RequireOrgMember(ctx context.Context, auth humatypes.AuthHeaders, orgID string, roles ...string) (sessionRes *dtos.SessionResponse, orgid string, err error) {
	sessionResp, err := h.Authenticate(ctx, auth)
	if err != nil {
		return nil, "", err
	}
	if orgID == "" && sessionResp.Session.ActiveOrganizationID != nil {
		orgID = *sessionResp.Session.ActiveOrganizationID
	}
	if orgID == "" {
		return nil, "", humatypes.NewError(http.StatusBadRequest, "organizationId is required when no organization is active")
	}
	member, err := h.Org.GetMember(ctx, orgID, sessionResp.User.ID)
	if err != nil || member == nil {
		return nil, "", autherr.ErrForbidden
	}
	if len(roles) == 0 {
		return sessionResp, orgID, nil
	}
	for _, allowed := range roles {
		if strings.EqualFold(string(member.Role), allowed) {
			return sessionResp, orgID, nil
		}
	}
	return nil, "", autherr.ErrForbidden
}

// rolesFor returns the org roles an operation requires (empty means any member).
func rolesFor(op consts.OperationId) []string {
	return OrgPermissionsMap[op].AllowedRoles
}

// targetMember loads memberID and ensures it belongs to orgID.
func (h *OrgHandler) targetMember(ctx context.Context, orgID, memberID string) (*models.Member, error) {
	member, err := h.Org.GetMemberByID(ctx, memberID)
	if err != nil || member == nil || member.OrganizationID != orgID {
		return nil, orgerrors.ErrMemberNotFound
	}
	return member, nil
}

// requireInvitee authenticates the caller and ensures the invitation was sent to their email.
func (h *OrgHandler) requireInvitee(ctx context.Context, auth humatypes.AuthHeaders, invitationID string) (*dtos.SessionResponse, error) {
	session, err := h.Authenticate(ctx, auth)
	if err != nil {
		return nil, err
	}
	inv, err := h.Org.GetInvitation(ctx, invitationID)
	if err != nil {
		return nil, err
	}
	if !h.isInvitee(ctx, session, inv.Email) {
		return nil, autherr.ErrForbidden
	}
	return session, nil
}

// isInvitee reports whether the caller's email matches inviteEmail (JWT claims carry no email, so fall back to the DB).
func (h *OrgHandler) isInvitee(ctx context.Context, session *dtos.SessionResponse, inviteEmail string) bool {
	email := session.User.Email
	if email == "" {
		email, _ = h.Org.UserEmail(ctx, session.User.ID)
	}
	return email != "" && strings.EqualFold(email, inviteEmail)
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
