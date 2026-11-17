package humaorg

import (
	"context"
	"net/http"
	"strings"

	"github.com/better-go-auth/goauth/src/common/consts"
	"github.com/better-go-auth/goauth/src/common/middleware"
	"github.com/better-go-auth/goauth/src/providers/authenticator"

	humaadapter "github.com/better-go-auth/goauth/src/app/adapters/huma"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/dtos"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
	orgerrors "github.com/better-go-auth/goauth/src/plugins/org/org-errors"
	orgsvc "github.com/better-go-auth/goauth/src/plugins/org/services"
	"github.com/better-go-auth/goauth/src/providers/access"
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
func (h *OrgHandler) RequireOrgMember(ctx context.Context, auth humatypes.AuthHeaders, orgID string, roles ...string) (sessionRes *dtos.SessionWithUser, orgid string, err error) {
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
	// a member holding one of roles (comma-separated multi-role values supported) passes
	if memberHasAnyRole(string(member.Role), roles) {
		return sessionResp, orgID, nil
	}
	return nil, "", autherr.ErrForbidden
}

// memberHasAnyRole reports whether any of the comma-separated member roles is in roles (case-insensitive).
func memberHasAnyRole(memberRole string, roles []string) bool {
	for _, r := range access.SplitRoles(memberRole) {
		for _, allowed := range roles {
			if strings.EqualFold(r, allowed) {
				return true
			}
		}
	}
	return false
}

// RequireOrgOp authenticates the caller, checks membership of orgID (the active organization when
// empty) and authorizes operation op:
//   - legacy mode: a role listed in OrgPermissionsMap[op].AllowedRoles passes (goauth's
//     operation table, unchanged); otherwise the better-auth permission mapped in
//     OrgRoutePermissions[op] is checked (Config.Roles, dynamic roles, multi-role).
//   - better-auth mode (AccessControl/AccessRoles configured): ops with a mapped permission are
//     decided by that permission only (better-auth hasPermission); other ops use the role table.
//   - in both modes, with dynamic access control and AuthMethod "ops"/"both", a dynamic role whose
//     Ops list contains the operation ID passes too (owner always passes HasOperation).
func (h *OrgHandler) RequireOrgOp(ctx context.Context, auth humatypes.AuthHeaders, orgID string, op consts.OperationId) (*dtos.SessionWithUser, string, error) {
	// Step 1: authenticate and require membership
	sessionResp, orgID, err := h.RequireOrgMember(ctx, auth, orgID)
	if err != nil {
		return nil, "", err
	}
	member, err := h.Org.GetMember(ctx, orgID, sessionResp.User.ID)
	if err != nil || member == nil {
		return nil, "", autherr.ErrForbidden
	}
	allowed := rolesFor(op)
	perm, hasPerm := OrgRoutePermissions[op]
	cfg := h.Org.OrgConfig()

	// Step 2: no restriction on this operation
	if len(allowed) == 0 && !hasPerm {
		return sessionResp, orgID, nil
	}
	// Step 3: goauth operation table (always in legacy mode; only for unmapped ops in better-auth mode)
	if (!cfg.BetterAuthMode() || !hasPerm) && memberHasAnyRole(string(member.Role), allowed) {
		return sessionResp, orgID, nil
	}
	// Step 4: better-auth permission mapped to the operation. In legacy mode the built-in
	// owner/admin/member roles stay governed by the operation table only (no new grants for them).
	if hasPerm {
		role := string(member.Role)
		if !cfg.BetterAuthMode() {
			role = withoutBuiltinRoles(role)
		}
		if role != "" {
			if ok, err := h.Org.HasPermissions(ctx, orgID, role, perm); err == nil && ok {
				return sessionResp, orgID, nil
			}
		}
	}
	// Step 5: goauth dynamic Ops (AuthMethod ops/both)
	if h.Org.DynamicAccessControlEnabled() && cfg.DynamicAccessControl != nil &&
		(cfg.DynamicAccessControl.AuthMethod == orgconfig.AuthMethodOperations || cfg.DynamicAccessControl.AuthMethod == orgconfig.AuthMethodBoth) {
		for _, r := range access.SplitRoles(string(member.Role)) {
			if ok, err := h.Org.HasOperation(ctx, orgID, r, op.Str()); err == nil && ok {
				return sessionResp, orgID, nil
			}
		}
	}
	return nil, "", autherr.ErrForbidden
}

// withoutBuiltinRoles drops goauth's built-in owner/admin/member names from a comma-separated role.
func withoutBuiltinRoles(role string) string {
	var out []string
	for _, r := range access.SplitRoles(role) {
		if r != models.OrgRoleOwner.Str() && r != models.OrgRoleAdmin.Str() && r != models.OrgRoleMember.Str() {
			out = append(out, r)
		}
	}
	return strings.Join(out, ",")
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
func (h *OrgHandler) requireInvitee(ctx context.Context, auth humatypes.AuthHeaders, invitationID string) (*dtos.SessionWithUser, error) {
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
func (h *OrgHandler) isInvitee(ctx context.Context, session *dtos.SessionWithUser, inviteEmail string) bool {
	email := session.User.Email
	if email == "" {
		email, _ = h.Org.UserEmail(ctx, session.User.ID)
	}
	return email != "" && strings.EqualFold(email, inviteEmail)
}

// defaultPagi returns sensible default pagination for org list endpoints.
func defaultPagi() models.Pagination {
	return models.Pagination{Limit: 50, Offset: 0, SortBy: "createdAt", SortDir: "desc"}
}

// Authenticate delegates authentication to the core authenticate function.
// It first checks if the request was already authenticated into context by middleware.
func (h *OrgHandler) Authenticate(ctx context.Context, auth humatypes.AuthHeaders) (*dtos.SessionWithUser, error) {
	if sess, ok := authenticator.SessionFromContext(ctx); ok && sess != nil {
		return sess, nil
	}
	if sess, ok := humaadapter.FromContext(ctx); ok && sess != nil {
		return sess, nil
	}
	if h.authFn != nil {
		return h.authFn(ctx, auth)
	}
	return nil, autherr.ErrUnauthorized
}
