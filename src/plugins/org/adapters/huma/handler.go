package humaorg

import (
	"context"
	"net/http"
	"strings"

	"github.com/better-go-auth/goauth/src/common/consts"
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
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/providers/access"
	"github.com/danielgtaylor/huma/v2"
)

// OrgHandler holds org-domain services; its routes are mounted through pluginkit.
type OrgHandler struct {
	Org orgsvc.IOrgService
	Cfg config.AuthConfig
	// Kit is the plugin runtime the routes are registered with (session resolver, origin check, disabled
	// routes, rate limiter, cookies).
	Kit    *pluginkit.Kit
	authFn authenticator.AuthenticateFunc
}

// NewOrgHandler creates a new OrgHandler. authFn authenticates direct handler calls that carry the
// credentials in their AuthHeaders instead of going through the HTTP session middleware.
func NewOrgHandler(org orgsvc.IOrgService, kit *pluginkit.Kit, authFn ...authenticator.AuthenticateFunc) *OrgHandler {
	var af authenticator.AuthenticateFunc
	if len(authFn) > 0 {
		af = authFn[0]
	}
	return &OrgHandler{Org: org, Kit: kit, authFn: af}
}

// register mounts an organization endpoint through pluginkit like every other plugin: goauth's one
// session resolver (cookie, bearer and access-token sessions; 401 UNAUTHORIZED without a session), the
// origin / CSRF check, disabled routes (DisabledPaths / DisabledOps) and better-auth's raw JSON bodies.
// op.Path is relative to BasePath.
func register[I, O any](api huma.API, h *OrgHandler, op huma.Operation, handler func(context.Context, *I) (*O, error)) {
	pluginkit.Register(h.Kit, api, pluginkit.Route{
		OperationID: op.OperationID, Method: op.Method, Path: op.Path, Summary: op.Summary,
		Description: op.Description, Tags: op.Tags, DefaultStatus: op.DefaultStatus, Access: pluginkit.Session,
	}, handler)
}

// opErrors are the errors the equivalent better-auth endpoint returns when no organization is given
// (and none is active), when the caller is not a member, and when the caller lacks the permission.
type opErrors struct {
	noOrg, notMember, denied *autherr.AuthError
}

// orgOpErrors maps operations to better-auth's per-route errors (plugins/organization/routes/*).
// Operations missing from the map use NO_ACTIVE_ORGANIZATION / FORBIDDEN / FORBIDDEN.
var orgOpErrors = map[consts.OperationId]opErrors{
	OrGetOrg:           {noOrg: orgerrors.ErrOrgNotFound, notMember: orgerrors.ErrUserNotMemberOfOrg403},
	OrUpdateOrg:        {noOrg: orgerrors.ErrOrgNotFound, notMember: orgerrors.ErrUserNotMemberOfOrg400, denied: orgerrors.ErrNotAllowedToUpdateOrganization},
	OrDeleteOrg:        {noOrg: orgerrors.ErrOrgNotFound, notMember: orgerrors.ErrUserNotMemberOfOrg400, denied: orgerrors.ErrNotAllowedToDeleteOrganization},
	OrSetActiveOrg:     {noOrg: orgerrors.ErrOrgNotFound, notMember: orgerrors.ErrUserNotMemberOfOrg403},
	OrInviteMember:     {noOrg: orgerrors.ErrOrgNotFound, notMember: orgerrors.ErrMemberNotFound, denied: orgerrors.ErrNotAllowedToInviteUsers},
	OrCancelInvitation: {noOrg: orgerrors.ErrInvitationNotFound, notMember: orgerrors.ErrMemberNotFound, denied: orgerrors.ErrNotAllowedToCancelInvitation},
	OrListInvitations: {
		noOrg:     autherr.New(autherr.BadRequest, "Organization ID is required", http.StatusBadRequest),
		notMember: autherr.New(autherr.Forbidden, "You are not a member of this organization", http.StatusForbidden),
	},
	OrGetMember:        {notMember: orgerrors.ErrNotAMemberOfThisOrganization},
	OrListMembers:      {notMember: orgerrors.ErrNotAMemberOfThisOrganization},
	OrUpdateMemberRole: {notMember: orgerrors.ErrMemberNotFound, denied: orgerrors.ErrNotAllowedToUpdateMember},
	OrRemoveMember:     {notMember: orgerrors.ErrMemberNotFound, denied: orgerrors.ErrNotAllowedToDeleteMember},
	OrCreateTeam:       {notMember: orgerrors.ErrNotAllowedToInviteUsers, denied: orgerrors.ErrNotAllowedToCreateTeams},
	OrUpdateTeam:       {notMember: orgerrors.ErrNotAllowedToUpdateTeam, denied: orgerrors.ErrNotAllowedToUpdateTeam},
	OrDeleteTeam:       {notMember: orgerrors.ErrNotAllowedToDeleteThisTeam, denied: orgerrors.ErrNotAllowedToDeleteTeams},
	OrListTeams:        {notMember: orgerrors.ErrNotAllowedToAccessOrganization},
	OrAddTeamMember:    {notMember: orgerrors.ErrUserNotMemberOfOrg400, denied: orgerrors.ErrNotAllowedToCreateTeamMember},
	OrRemoveTeamMember: {notMember: orgerrors.ErrUserNotMemberOfOrg400, denied: orgerrors.ErrNotAllowedToRemoveTeamMember},
	OrGetActiveMemberRole: {
		notMember: orgerrors.ErrNotAMemberOfThisOrganization,
	},
}

// errorsFor returns the better-auth errors of op, with goauth's defaults for unmapped operations.
func errorsFor(op consts.OperationId) opErrors {
	e := orgOpErrors[op]
	if e.noOrg == nil {
		e.noOrg = orgerrors.ErrNoActiveOrganization
	}
	if e.notMember == nil {
		e.notMember = autherr.ErrForbidden
	}
	if e.denied == nil {
		e.denied = autherr.ErrForbidden
	}
	return e
}

// RequireOrgMember authenticates the caller and checks, against the member table, that they belong to
// orgID (the session's active organization when orgID is empty) with one of roles (any role when empty).
func (h *OrgHandler) RequireOrgMember(ctx context.Context, auth humatypes.AuthHeaders, orgID string, roles ...string) (sessionRes *dtos.SessionWithUser, orgid string, err error) {
	return h.requireMember(ctx, auth, orgID, errorsFor(""), roles...)
}

// requireMember is RequireOrgMember with the better-auth errors of one route.
func (h *OrgHandler) requireMember(ctx context.Context, auth humatypes.AuthHeaders, orgID string, errs opErrors, roles ...string) (*dtos.SessionWithUser, string, error) {
	// Step 1: authenticate and resolve the organization (explicit, else the active one)
	sessionResp, err := h.Authenticate(ctx, auth)
	if err != nil {
		return nil, "", err
	}
	if orgID == "" && sessionResp.Session.ActiveOrganizationID != nil {
		orgID = *sessionResp.Session.ActiveOrganizationID
	}
	if orgID == "" {
		return nil, "", errs.noOrg
	}

	// Step 2: membership
	member, err := h.Org.GetMember(ctx, orgID, sessionResp.User.ID)
	if err != nil || member == nil {
		return nil, "", errs.notMember
	}
	// Step 3: role restriction
	if len(roles) == 0 {
		return sessionResp, orgID, nil
	}
	// a member holding one of roles (comma-separated multi-role values supported) passes
	if memberHasAnyRole(string(member.Role), roles) {
		return sessionResp, orgID, nil
	}
	return nil, "", errs.denied
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
	errs := errorsFor(op)
	sessionResp, orgID, err := h.requireMember(ctx, auth, orgID, errs)
	if err != nil {
		return nil, "", err
	}
	member, err := h.Org.GetMember(ctx, orgID, sessionResp.User.ID)
	if err != nil || member == nil {
		return nil, "", errs.notMember
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
	return nil, "", errs.denied
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
		return nil, orgerrors.ErrNotRecipientOfInvitation
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

// Authenticate returns the caller's session: the one goauth's session resolver attached to the request (a
// full session with the user, also for access-token JWTs), else the claims a token middleware put in the
// context, else authFn for direct handler calls.
func (h *OrgHandler) Authenticate(ctx context.Context, auth humatypes.AuthHeaders) (*dtos.SessionWithUser, error) {
	if sess, ok := humaadapter.FromContext(ctx); ok && sess != nil {
		return sess, nil
	}
	if sess, ok := authenticator.SessionFromContext(ctx); ok && sess != nil {
		return sess, nil
	}
	if h.authFn != nil {
		return h.authFn(ctx, auth)
	}
	return nil, autherr.ErrUnauthorized
}
