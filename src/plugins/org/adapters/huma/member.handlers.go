package humaorg

import (
	"context"
	"net/http"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	orgdtos "github.com/better-go-auth/goauth/src/plugins/org/dtos"
	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
)

// ─── Member ───────────────────────────────────────────────────────────────────

func (h *OrgHandler) GetMember(ctx context.Context, input *GetMemberInput) (*humatypes.HumaRes[orgdtos.MemberResponse], error) {
	session, orgID, err := h.RequireOrgMember(ctx, input.AuthHeaders, input.OrganizationID, rolesFor(OrGetMember)...)
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

type MemberResp struct {
	Members []orgdtos.MemberResponse `json:"members"`
	Total   int64                    `json:"total"`
}

func (h *OrgHandler) ListMembers(ctx context.Context, input *ListMembersInput) (*humatypes.HumaRes[MemberResp], error) {
	_, orgID, err := h.RequireOrgMember(ctx, input.AuthHeaders, input.OrganizationID, rolesFor(OrListMembers)...)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	members, total, err := h.Org.ListMembers(ctx, orgID, defaultPagi())
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	resps := make([]orgdtos.MemberResponse, 0, len(members))
	for i := range members {
		resps = append(resps, *orgdtos.MemberToResponse(&members[i]))
	}
	return humatypes.MakeRes(MemberResp{Members: resps, Total: total}, http.StatusOK), nil
}

func (h *OrgHandler) UpdateMemberRole(ctx context.Context, input *UpdateMemberRoleInput) (*humatypes.HumaRes[orgdtos.MemberResponse], error) {
	// Step 1: Verify membership and resolve organizationId
	session, orgID, err := h.RequireOrgMember(ctx, input.AuthHeaders, input.Body.OrganizationID, rolesFor(OrUpdateMemberRole)...)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	input.Body.OrganizationID = orgID
	// Step 2: Load target member and guard against demoting owner
	target, err := h.targetMember(ctx, orgID, input.Body.MemberID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	if target.Role == orgmodels.OrgRoleOwner && input.Body.Role != orgmodels.OrgRoleOwner {
		return nil, humatypes.RespondErr(autherr.New("CANNOT_DEMOTE_OWNER", "Cannot change the owner's role", http.StatusBadRequest))
	}
	// Step 3: Update role in service layer
	member, err := h.Org.UpdateMemberRole(ctx, input.Body, session.User.ID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeResPtr(orgdtos.MemberToResponse(member), http.StatusOK), nil
}

func (h *OrgHandler) RemoveMember(ctx context.Context, input *RemoveMemberInput) (*humatypes.SuccessOutput, error) {
	// Step 1: Verify membership and resolve organizationId
	sessionResp, orgID, err := h.RequireOrgMember(ctx, input.AuthHeaders, input.Body.OrganizationID, rolesFor(OrRemoveMember)...)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	input.Body.OrganizationID = orgID
	// Step 2: Resolve memberId from memberIdOrEmail if memberId was omitted
	if input.Body.MemberID == "" && input.Body.MemberIDOrEmail != "" {
		resolvedID, rErr := h.Org.ResolveMemberID(ctx, orgID, input.Body.MemberIDOrEmail)
		if rErr != nil {
			return nil, humatypes.RespondErr(rErr)
		}
		input.Body.MemberID = resolvedID
	}
	// Step 3: Load target member and prevent removing owner
	target, err := h.targetMember(ctx, orgID, input.Body.MemberID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	if target.Role == orgmodels.OrgRoleOwner {
		return nil, humatypes.RespondErr(autherr.New("CANNOT_REMOVE_OWNER", "Cannot remove the organization owner", http.StatusBadRequest))
	}
	// Step 4: Remove member via service layer
	if err := h.Org.RemoveMember(ctx, input.Body, sessionResp.User.ID); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.SuccessRes(http.StatusOK), nil
}

// LeaveOrganization allows an authenticated user to voluntarily leave an organization.
func (h *OrgHandler) LeaveOrganization(ctx context.Context, input *LeaveOrgInput) (*humatypes.SuccessOutput, error) {
	// Step 1: Authenticate requesting user
	sessionResp, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}

	// Step 2: Leave organization via service layer (blocks sole owner and clears active org if matched)
	if err := h.Org.LeaveOrganization(ctx, input.Body.OrganizationID, sessionResp.User.ID, sessionResp.Session.ID); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.SuccessRes(http.StatusOK), nil
}
