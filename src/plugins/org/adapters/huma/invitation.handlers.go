package humaorg

import (
	"context"
	"net/http"

	humatypes "github.com/better-go-auth/goauth/src/common/types"
	orgdtos "github.com/better-go-auth/goauth/src/plugins/org/dtos"
)

// ─── Invitation ───────────────────────────────────────────────────────────────

func (h *OrgHandler) InviteMember(ctx context.Context, input *InviteMemberInput) (*humatypes.HumaRes[orgdtos.InvitationResponse], error) {
	// Step 1: Verify membership and resolve organizationId (falls back to active organization)
	session, orgID, err := h.RequireOrgOp(ctx, input.AuthHeaders, input.Body.OrganizationID, OrInviteMember)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	input.Body.OrganizationID = orgID
	// Step 2: Create and dispatch invitation
	inv, err := h.Org.InviteMember(ctx, session.User.ID, input.Body)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeRes(*orgdtos.InvitationToResponse(inv), http.StatusCreated), nil
}

func (h *OrgHandler) GetInvitation(ctx context.Context, input *GetInvitationInput) (*humatypes.HumaRes[orgdtos.InvitationResponse], error) {
	// Step 1: Authenticate caller and resolve invitation ID from ?invitationId= or ?id=
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	invID := input.InvitationID
	if invID == "" {
		invID = input.ID
	}
	// Step 2: Fetch invitation (enforcing RequireEmailVerificationOnInvitation when caller is recipient)
	inv, err := h.Org.GetInvitationForUser(ctx, invID, session.User.ID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	// Step 3: Visible to the invitee, or to org members who may manage invitations
	if !h.isInvitee(ctx, session, inv.Email) {
		if _, _, err := h.RequireOrgOp(ctx, input.AuthHeaders, inv.OrganizationID, OrListInvitations); err != nil {
			return nil, humatypes.RespondErr(err)
		}
	}
	return humatypes.MakeRes(*orgdtos.InvitationToResponse(inv), http.StatusOK), nil
}

func (h *OrgHandler) AcceptInvitation(ctx context.Context, input *HumaInvitationInput) (*humatypes.SuccessOutput, error) {
	session, err := h.requireInvitee(ctx, input.AuthHeaders, input.Body.InvitationID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	if err := h.Org.AcceptInvitation(ctx, input.Body.InvitationID, session.User.ID); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.SuccessRes(http.StatusOK), nil
}

func (h *OrgHandler) RejectInvitation(ctx context.Context, input *HumaInvitationInput) (*humatypes.SuccessOutput, error) {
	session, err := h.requireInvitee(ctx, input.AuthHeaders, input.Body.InvitationID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	if err := h.Org.RejectInvitation(ctx, input.Body.InvitationID, session.User.ID); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.SuccessRes(http.StatusOK), nil
}

func (h *OrgHandler) CancelInvitation(ctx context.Context, input *HumaInvitationInput) (*humatypes.SuccessOutput, error) {
	inv, err := h.Org.GetInvitation(ctx, input.Body.InvitationID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}

	sesRes, _, err := h.RequireOrgOp(ctx, input.AuthHeaders, inv.OrganizationID, OrCancelInvitation)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	if err := h.Org.CancelInvitation(ctx, input.Body.InvitationID, sesRes.User.ID); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.SuccessRes(http.StatusOK), nil
}

type InvitationResp struct {
	Invitations []orgdtos.InvitationResponse `json:"invitations"`
}

func (h *OrgHandler) ListInvitations(ctx context.Context, input *ListInvitationsInput) (*humatypes.HumaRes[InvitationResp], error) {
	_, orgID, err := h.RequireOrgOp(ctx, input.AuthHeaders, input.OrganizationID, OrListInvitations)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	invs, _, err := h.Org.ListInvitations(ctx, orgID, defaultPagi())
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	resps := make([]orgdtos.InvitationResponse, 0, len(invs))
	for i := range invs {
		resps = append(resps, *orgdtos.InvitationToResponse(&invs[i]))
	}
	return humatypes.MakeRes(InvitationResp{Invitations: resps}, http.StatusOK), nil
}

// ListUserInvitations returns pending invitations addressed to the authenticated user's email.
func (h *OrgHandler) ListUserInvitations(ctx context.Context, input *ListUserInvitationsInput) (*humatypes.HumaRes[InvitationResp], error) {
	// Step 1: Authenticate requesting user
	sessionResp, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}

	// Step 2: Resolve user email from session user or fallback lookup
	email := sessionResp.User.Email
	if email == "" {
		email, err = h.Org.UserEmail(ctx, sessionResp.User.ID)
		if err != nil {
			return nil, humatypes.RespondErr(err)
		}
	}

	// Step 3: Fetch pending invitations for the user's email
	invs, err := h.Org.ListUserInvitations(ctx, email)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}

	// Step 4: Convert invitations with enriched org/inviter fields
	resps := make([]orgdtos.InvitationResponse, 0, len(invs))
	for i := range invs {
		resps = append(resps, *orgdtos.InvitationToResponse(&invs[i]))
	}
	return humatypes.MakeRes(InvitationResp{Invitations: resps}, http.StatusOK), nil
}
