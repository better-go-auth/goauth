package humaorg

import (
	"context"
	"net/http"
	"strings"

	humatypes "github.com/better-go-auth/goauth/src/common/types"
	orgdtos "github.com/better-go-auth/goauth/src/plugins/org/dtos"
	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
	orgerrors "github.com/better-go-auth/goauth/src/plugins/org/org-errors"
)

// ─── Member ───────────────────────────────────────────────────────────────────

// GetMember is goauth's GET /organization/get-member (not a better-auth route): a member of the organization
// (the caller by default) with its user.
func (h *OrgHandler) GetMember(ctx context.Context, input *GetMemberInput) (*humatypes.HumaRes[orgdtos.MemberResponse], error) {
	session, orgID, err := h.RequireOrgOp(ctx, input.AuthHeaders, input.OrganizationID, OrGetMember)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	uid := input.UserID
	if uid == "" {
		uid = session.User.ID
	}
	member, err := h.Org.GetMember(ctx, orgID, uid)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeResPtr(orgdtos.MemberToResponse(member), http.StatusOK), nil
}

// GetActiveMember is better-auth's GET /organization/get-active-member: the caller's membership in the
// active organization, with {id, name, email, image} of the user.
func (h *OrgHandler) GetActiveMember(ctx context.Context, input *GetActiveMemberInput) (*humatypes.HumaRes[orgdtos.MemberResponse], error) {
	// Step 1: Authenticate caller session
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	// Step 2: only the active organization counts (no query parameters)
	if session.Session.ActiveOrganizationID == nil || *session.Session.ActiveOrganizationID == "" {
		return nil, humatypes.RespondErr(orgerrors.ErrNoActiveOrganization)
	}
	// Step 3: the caller's membership (400 MEMBER_NOT_FOUND when they left the organization)
	member, err := h.Org.GetMember(ctx, *session.Session.ActiveOrganizationID, session.User.ID)
	if err != nil || member == nil {
		return nil, humatypes.RespondErr(orgerrors.ErrMemberNotFound)
	}
	return humatypes.MakeResPtr(orgdtos.MemberToResponse(member), http.StatusOK), nil
}

// GetActiveMemberRole is better-auth's GET /organization/get-active-member-role: {role} of the caller, or of
// ?userId= when the caller is a member of the organization (organizationSlug, organizationId or the active one).
func (h *OrgHandler) GetActiveMemberRole(ctx context.Context, input *GetActiveMemberRoleInput) (*humatypes.HumaRes[orgdtos.ActiveMemberRoleResponse], error) {
	// Step 1: Authenticate caller session
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	// Step 2: Resolve the organization: slug, then ID, then the active one
	orgID := input.OrganizationID
	if orgID == "" && session.Session.ActiveOrganizationID != nil {
		orgID = *session.Session.ActiveOrganizationID
	}
	if input.OrganizationSlug != "" {
		org, err := h.Org.GetOrganizationBySlug(ctx, input.OrganizationSlug)
		if err != nil || org == nil {
			return nil, humatypes.RespondErr(orgerrors.ErrOrgNotFound)
		}
		orgID = org.ID
	}
	if orgID == "" {
		return nil, humatypes.RespondErr(orgerrors.ErrNoActiveOrganization)
	}
	// Step 3: the caller must be a member
	caller, err := h.Org.GetMember(ctx, orgID, session.User.ID)
	if err != nil || caller == nil {
		return nil, humatypes.RespondErr(orgerrors.ErrNotAMemberOfThisOrganization)
	}
	if input.UserID == "" {
		return humatypes.MakeRes(orgdtos.ActiveMemberRoleResponse{Role: string(caller.Role)}, http.StatusOK), nil
	}
	// Step 4: another member's role (better-auth answers the same 403 when that user is not a member)
	target, err := h.Org.GetMember(ctx, orgID, input.UserID)
	if err != nil || target == nil {
		return nil, humatypes.RespondErr(orgerrors.ErrNotAMemberOfThisOrganization)
	}
	return humatypes.MakeRes(orgdtos.ActiveMemberRoleResponse{Role: string(target.Role)}, http.StatusOK), nil
}

type MemberResp struct {
	Members []orgdtos.MemberResponse `json:"members"`
	Total   int64                    `json:"total"`
}

// ListMembers is better-auth's GET /organization/list-members: {members (with users), total}.
func (h *OrgHandler) ListMembers(ctx context.Context, input *ListMembersInput) (*humatypes.HumaRes[MemberResp], error) {
	// Step 1: organizationSlug wins over organizationId
	targetOrgID := input.OrganizationID
	if input.OrganizationSlug != "" {
		org, err := h.Org.GetOrganizationBySlug(ctx, input.OrganizationSlug)
		if err != nil || org == nil {
			return nil, humatypes.RespondErr(orgerrors.ErrOrgNotFound)
		}
		targetOrgID = org.ID
	}
	// Step 2: membership
	_, orgID, err := h.RequireOrgOp(ctx, input.AuthHeaders, targetOrgID, OrListMembers)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	// Step 3: page (default limit: the membership limit, else 100, as in better-auth's adapter)
	pagi := orgmodels.Pagination{Limit: input.Limit, Offset: input.Offset, SortBy: input.SortBy, SortDir: input.SortDirection}
	if pagi.Limit <= 0 {
		pagi.Limit = 100
		if l := h.Org.OrgConfig().MembershipLimit; l != nil && *l > 0 {
			pagi.Limit = *l
		}
	}
	if pagi.SortBy == "" {
		pagi.SortBy, pagi.SortDir = "createdAt", "asc"
	} else if pagi.SortDir == "" {
		pagi.SortDir = "asc"
	}
	members, total, err := h.Org.ListMembers(ctx, orgID, pagi)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	resps := make([]orgdtos.MemberResponse, 0, len(members))
	for i := range members {
		resps = append(resps, *orgdtos.MemberToResponse(&members[i]))
	}
	return humatypes.MakeRes(MemberResp{Members: resps, Total: total}, http.StatusOK), nil
}

// UpdateMemberRole is better-auth's POST /organization/update-member-role: the updated member row.
func (h *OrgHandler) UpdateMemberRole(ctx context.Context, input *UpdateMemberRoleInput) (*humatypes.HumaRes[orgdtos.MemberResponse], error) {
	// Step 1: Verify membership, member:update permission and resolve organizationId
	session, orgID, err := h.RequireOrgOp(ctx, input.AuthHeaders, input.Body.OrganizationID, OrUpdateMemberRole)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	input.Body.OrganizationID = orgID
	// Step 2: Update role in service layer (target lookup and better-auth's owner rules live there)
	member, err := h.Org.UpdateMemberRole(ctx, input.Body, session.User.ID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeResPtr(orgdtos.MemberWithoutUser(member), http.StatusOK), nil
}

// RemoveMember is better-auth's POST /organization/remove-member: {member} of the removed member.
func (h *OrgHandler) RemoveMember(ctx context.Context, input *RemoveMemberInput) (*humatypes.HumaRes[orgdtos.RemovedMemberResponse], error) {
	// Step 1: Verify membership and resolve organizationId. Like better-auth, the owner rules run before the
	// member:delete permission check; both live in the service.
	sessionResp, orgID, err := h.requireMember(ctx, input.AuthHeaders, input.Body.OrganizationID, errorsFor(OrRemoveMember))
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	input.Body.OrganizationID = orgID
	// Step 2: Resolve the member: memberIdOrEmail (an email when it contains "@"), or goauth's memberId
	var target *orgmodels.Member
	byEmail := false
	switch {
	case input.Body.MemberIDOrEmail != "" && strings.Contains(input.Body.MemberIDOrEmail, "@"):
		byEmail = true
		resolvedID, rErr := h.Org.ResolveMemberID(ctx, orgID, input.Body.MemberIDOrEmail)
		if rErr != nil {
			return nil, humatypes.RespondErr(orgerrors.ErrMemberNotFound)
		}
		target, err = h.Org.GetMemberByID(ctx, resolvedID)
	case input.Body.MemberIDOrEmail != "":
		target, err = h.Org.GetMemberByID(ctx, input.Body.MemberIDOrEmail)
	default:
		target, err = h.Org.GetMemberByID(ctx, input.Body.MemberID)
	}
	if err != nil || target == nil {
		return nil, humatypes.RespondErr(orgerrors.ErrMemberNotFound)
	}
	input.Body.MemberID = target.ID
	// Step 3: Remove member via service layer
	if err := h.Org.RemoveMember(ctx, input.Body, sessionResp.User.ID); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	// Step 4: a member removing themselves loses the active organization
	if target.UserID == sessionResp.User.ID && sessionResp.Session.ActiveOrganizationID != nil && *sessionResp.Session.ActiveOrganizationID == orgID {
		_, _ = h.Org.SetActiveOrganization(ctx, sessionResp.Session.ID, nil, sessionResp.User.ID, "")
	}
	// Step 5: better-auth returns the member with its user when looked up by email, without it by ID
	removed := orgdtos.MemberWithoutUser(target)
	if byEmail {
		removed = orgdtos.MemberToResponse(target)
	}
	return humatypes.MakeRes(orgdtos.RemovedMemberResponse{Member: *removed}, http.StatusOK), nil
}

// LeaveOrganization is better-auth's POST /organization/leave: the caller's former membership.
func (h *OrgHandler) LeaveOrganization(ctx context.Context, input *LeaveOrgInput) (*humatypes.HumaRes[orgdtos.MemberResponse], error) {
	// Step 1: Authenticate requesting user
	sessionResp, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	// Step 2: the membership being left (returned to the client)
	member, err := h.Org.GetMember(ctx, input.Body.OrganizationID, sessionResp.User.ID)
	if err != nil || member == nil {
		return nil, humatypes.RespondErr(orgerrors.ErrMemberNotFound)
	}

	// Step 3: Leave organization via service layer (blocks sole owner and clears active org if matched)
	if err := h.Org.LeaveOrganization(ctx, input.Body.OrganizationID, sessionResp.User.ID, sessionResp.Session.ID); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeResPtr(orgdtos.MemberToResponse(member), http.StatusOK), nil
}
