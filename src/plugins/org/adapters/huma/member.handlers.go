package humaorg

import (
	"context"
	"net/http"

	orgdtos "github.com/better-go-auth/goauth/src/plugins/org/dtos"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
)

// ─── Member ───────────────────────────────────────────────────────────────────

func (h *OrgHandler) GetMember(ctx context.Context, input *GetMemberInput) (*humatypes.HumaRes[orgdtos.MemberResponse], error) {
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	uid := input.UserID
	if uid == "" {
		uid = session.User.ID
	}
	member, err := h.Org.GetMember(ctx, input.OrganizationID, uid)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.Ptr(humatypes.MakeRes(*orgdtos.MemberToResponse(member), http.StatusOK)), nil
}

func (h *OrgHandler) ListMembers(ctx context.Context, input *ListMembersInput) (*humatypes.HumaRes[struct {
	Members []orgdtos.MemberResponse `json:"members"`
	Total   int64                    `json:"total"`
}], error) {
	if _, err := h.Authenticate(ctx, input.AuthHeaders); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	members, total, err := h.Org.ListMembers(ctx, input.OrganizationID, defaultPagi())
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	resps := make([]orgdtos.MemberResponse, 0, len(members))
	for i := range members {
		resps = append(resps, *orgdtos.MemberToResponse(&members[i]))
	}
	return humatypes.Ptr(humatypes.MakeRes(struct {
		Members []orgdtos.MemberResponse `json:"members"`
		Total   int64                    `json:"total"`
	}{Members: resps, Total: total}, http.StatusOK)), nil
}

func (h *OrgHandler) UpdateMemberRole(ctx context.Context, input *UpdateMemberRoleInput) (*humatypes.HumaRes[orgdtos.MemberResponse], error) {
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	if _, err := h.RequireOrgRoles(ctx, input.AuthHeaders, "owner"); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	member, err := h.Org.UpdateMemberRole(ctx, input.Body, session.User.ID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.Ptr(humatypes.MakeRes(*orgdtos.MemberToResponse(member), http.StatusOK)), nil
}

func (h *OrgHandler) RemoveMember(ctx context.Context, input *RemoveMemberInput) (*humatypes.SuccessOutput, error) {
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	if _, err := h.RequireOrgRoles(ctx, input.AuthHeaders, "admin", "owner"); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	if err := h.Org.RemoveMember(ctx, input.Body, session.User.ID); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return &humatypes.SuccessOutput{Body: humatypes.SuccessBody{Success: true}}, nil
}
