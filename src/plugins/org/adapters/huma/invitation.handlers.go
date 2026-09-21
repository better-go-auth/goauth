package humaorg

import (
	"context"
	"net/http"

	humatypes "github.com/better-go-auth/goauth/src/common/types"
	orgdtos "github.com/better-go-auth/goauth/src/plugins/org/dtos"
)

// ─── Invitation ───────────────────────────────────────────────────────────────

func (h *OrgHandler) InviteMember(ctx context.Context, input *InviteMemberInput) (*humatypes.HumaRes[orgdtos.InvitationResponse], error) {
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	if _, err := h.RequireOrgRoles(ctx, input.AuthHeaders, "admin", "owner"); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	inv, err := h.Org.InviteMember(ctx, session.User.ID, input.Body)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeRes(*orgdtos.InvitationToResponse(inv), http.StatusCreated), nil
}

func (h *OrgHandler) GetInvitation(ctx context.Context, input *GetInvitationInput) (*humatypes.HumaRes[orgdtos.InvitationResponse], error) {
	if _, err := h.Authenticate(ctx, input.AuthHeaders); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	inv, err := h.Org.GetInvitation(ctx, input.InvitationID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeRes(*orgdtos.InvitationToResponse(inv), http.StatusOK), nil
}

func (h *OrgHandler) AcceptInvitation(ctx context.Context, input *HumaInvitationInput) (*humatypes.SuccessOutput, error) {
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	if err := h.Org.AcceptInvitation(ctx, input.Body.InvitationID, session.User.ID); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.SuccessRes(http.StatusOK), nil
}

func (h *OrgHandler) RejectInvitation(ctx context.Context, input *HumaInvitationInput) (*humatypes.SuccessOutput, error) {
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	if err := h.Org.RejectInvitation(ctx, input.Body.InvitationID, session.User.ID); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.SuccessRes(http.StatusOK), nil
}

func (h *OrgHandler) CancelInvitation(ctx context.Context, input *HumaInvitationInput) (*humatypes.SuccessOutput, error) {
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	if err := h.Org.CancelInvitation(ctx, input.Body.InvitationID, session.User.ID); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.SuccessRes(http.StatusOK), nil
}

type InvitationResp struct {
	Invitations []orgdtos.InvitationResponse `json:"invitations"`
}

func (h *OrgHandler) ListInvitations(ctx context.Context, input *ListInvitationsInput) (*humatypes.HumaRes[InvitationResp], error) {
	if _, err := h.Authenticate(ctx, input.AuthHeaders); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	invs, _, err := h.Org.ListInvitations(ctx, input.OrganizationID, defaultPagi())
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	resps := make([]orgdtos.InvitationResponse, 0, len(invs))
	for i := range invs {
		resps = append(resps, *orgdtos.InvitationToResponse(&invs[i]))
	}
	return humatypes.MakeRes(InvitationResp{Invitations: resps}, http.StatusOK), nil
}
