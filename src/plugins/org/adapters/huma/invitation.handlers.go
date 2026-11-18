package humaorg

import (
	"context"
	"net/http"
	"strings"
	"time"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	orgdtos "github.com/better-go-auth/goauth/src/plugins/org/dtos"
	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
	orgerrors "github.com/better-go-auth/goauth/src/plugins/org/org-errors"
	orgsvc "github.com/better-go-auth/goauth/src/plugins/org/services"
)

// errInvitationNotFoundBang is get-invitation's APIError.fromStatus("BAD_REQUEST", {message: "Invitation not found!"}).
var errInvitationNotFoundBang = autherr.New(autherr.BadRequest, "Invitation not found!", http.StatusBadRequest)

// invitationRow is the raw better-auth invitation row (no organization or inviter enrichment).
func invitationRow(inv *orgmodels.Invitation) *orgdtos.InvitationResponse {
	resp := orgdtos.InvitationToResponse(inv)
	if resp != nil {
		resp.OrganizationName, resp.OrganizationSlug, resp.Inviter = nil, nil, nil
	}
	return resp
}

// ─── Invitation ───────────────────────────────────────────────────────────────

// InviteMember is better-auth's POST /organization/invite-member: 200 with the invitation row.
func (h *OrgHandler) InviteMember(ctx context.Context, input *InviteMemberInput) (*humatypes.HumaRes[orgdtos.InvitationResponse], error) {
	// Step 1: Verify membership and resolve organizationId (falls back to active organization)
	session, orgID, err := h.RequireOrgOp(ctx, input.AuthHeaders, input.Body.OrganizationID, OrInviteMember)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	input.Body.OrganizationID = orgID
	// Step 2: only an owner (creator role) may invite someone as owner
	creatorRole := h.creatorRole()
	if orgsvc.HasRole(string(input.Body.Role), creatorRole) {
		if inviter, mErr := h.Org.GetMember(ctx, orgID, session.User.ID); mErr != nil || inviter == nil || !orgsvc.HasRole(string(inviter.Role), creatorRole) {
			return nil, humatypes.RespondErr(orgerrors.ErrNotAllowedToInviteWithRole)
		}
	}
	// Step 3: Create and dispatch invitation
	inv, err := h.Org.InviteMember(ctx, session.User.ID, input.Body)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeRes(*invitationRow(inv), http.StatusOK), nil
}

// GetInvitation is better-auth's GET /organization/get-invitation?id=: a pending invitation addressed to the
// caller, with organizationName, organizationSlug and inviterEmail.
func (h *OrgHandler) GetInvitation(ctx context.Context, input *GetInvitationInput) (*humatypes.HumaRes[orgdtos.InvitationDetailsResponse], error) {
	// Step 1: Authenticate caller and resolve invitation ID from ?id= (or goauth's ?invitationId=)
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	invID := input.ID
	if invID == "" {
		invID = input.InvitationID
	}
	// Step 2: only pending, unexpired invitations are visible
	inv, err := h.Org.GetInvitation(ctx, invID)
	if err != nil || inv == nil || inv.Status != orgmodels.InvitationPending || time.Now().After(inv.ExpiresAt) {
		return nil, humatypes.RespondErr(errInvitationNotFoundBang)
	}
	// Step 3: only the recipient may read it
	if !h.isInvitee(ctx, session, inv.Email) {
		return nil, humatypes.RespondErr(orgerrors.ErrNotRecipientOfInvitation)
	}
	// Step 4: RequireEmailVerificationOnInvitation
	if _, err := h.Org.GetInvitationForUser(ctx, invID, session.User.ID); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	// Step 5: organization and inviter (who must still be a member)
	org, err := h.Org.GetOrganization(ctx, inv.OrganizationID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	inviter, err := h.Org.GetMember(ctx, inv.OrganizationID, inv.InviterID)
	if err != nil || inviter == nil {
		return nil, humatypes.RespondErr(orgerrors.ErrInviterNoLongerMember)
	}
	out := orgdtos.InvitationDetailsResponse{InvitationResponse: *invitationRow(inv)}
	name, slug := org.Name, org.Slug
	out.OrganizationName, out.OrganizationSlug = &name, &slug
	if inviter.User != nil {
		out.InviterEmail = inviter.User.Email
	} else {
		out.InviterEmail, _ = h.Org.UserEmail(ctx, inv.InviterID)
	}
	return humatypes.MakeRes(out, http.StatusOK), nil
}

// AcceptInvitation is better-auth's POST /organization/accept-invitation: {invitation, member}. The
// organization becomes the active one.
func (h *OrgHandler) AcceptInvitation(ctx context.Context, input *HumaInvitationInput) (*humatypes.HumaRes[orgdtos.InvitationResultResponse], error) {
	// Step 1: the caller must be the recipient
	session, err := h.requireInvitee(ctx, input.AuthHeaders, input.Body.InvitationID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	// Step 2: accept (status, expiry, verification and membership-limit checks live in the service)
	if err := h.Org.AcceptInvitation(ctx, input.Body.InvitationID, session.User.ID); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	inv, err := h.Org.GetInvitation(ctx, input.Body.InvitationID)
	if err != nil {
		return nil, humatypes.RespondErr(orgerrors.ErrFailedToRetrieveInvitation)
	}
	// Step 3: better-auth makes the organization active (and the invitation's single team)
	if session.Session.ID != "" {
		_, _ = h.Org.SetActiveOrganization(ctx, session.Session.ID, &inv.OrganizationID, session.User.ID, session.User.Role)
		if h.Org.TeamsEnabled() && inv.TeamID != nil && *inv.TeamID != "" && !strings.Contains(*inv.TeamID, ",") {
			_, _ = h.Org.SetActiveTeam(ctx, session.Session.ID, inv.TeamID, session.User.ID)
		}
	}
	// Step 4: the invitation and the new membership (raw member row)
	out := orgdtos.InvitationResultResponse{Invitation: invitationRow(inv)}
	if member, mErr := h.Org.GetMember(ctx, inv.OrganizationID, session.User.ID); mErr == nil && member != nil {
		out.Member = orgdtos.MemberWithoutUser(member)
	}
	return humatypes.MakeRes(out, http.StatusOK), nil
}

// RejectInvitation is better-auth's POST /organization/reject-invitation: {invitation, member: null}.
func (h *OrgHandler) RejectInvitation(ctx context.Context, input *HumaInvitationInput) (*humatypes.HumaRes[orgdtos.InvitationResultResponse], error) {
	// Step 1: the caller must be the recipient
	session, err := h.requireInvitee(ctx, input.AuthHeaders, input.Body.InvitationID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	// Step 2: reject, then return the updated invitation
	if err := h.Org.RejectInvitation(ctx, input.Body.InvitationID, session.User.ID); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	inv, err := h.Org.GetInvitation(ctx, input.Body.InvitationID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeRes(orgdtos.InvitationResultResponse{Invitation: invitationRow(inv)}, http.StatusOK), nil
}

// CancelInvitation is better-auth's POST /organization/cancel-invitation: the canceled invitation.
func (h *OrgHandler) CancelInvitation(ctx context.Context, input *HumaInvitationInput) (*humatypes.HumaRes[orgdtos.InvitationResponse], error) {
	// Step 1: the invitation decides the organization
	inv, err := h.Org.GetInvitation(ctx, input.Body.InvitationID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	// Step 2: membership and invitation:cancel permission
	sesRes, _, err := h.RequireOrgOp(ctx, input.AuthHeaders, inv.OrganizationID, OrCancelInvitation)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	// Step 3: cancel and return the updated row
	if err := h.Org.CancelInvitation(ctx, input.Body.InvitationID, sesRes.User.ID); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	canceled, err := h.Org.GetInvitation(ctx, input.Body.InvitationID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeRes(*invitationRow(canceled), http.StatusOK), nil
}

// ListInvitations is better-auth's GET /organization/list-invitations: an array of the organization's
// invitations, readable by any member.
func (h *OrgHandler) ListInvitations(ctx context.Context, input *ListInvitationsInput) (*humatypes.HumaRes[[]orgdtos.InvitationResponse], error) {
	// Step 1: membership (no permission needed, as in better-auth)
	_, orgID, err := h.RequireOrgOp(ctx, input.AuthHeaders, input.OrganizationID, OrListInvitations)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	// Step 2: every invitation of the organization
	invs, _, err := h.Org.ListInvitations(ctx, orgID, orgmodels.Pagination{Limit: 1000})
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	resps := make([]orgdtos.InvitationResponse, 0, len(invs))
	for i := range invs {
		resps = append(resps, *invitationRow(&invs[i]))
	}
	return humatypes.MakeRes(resps, http.StatusOK), nil
}

// ListUserInvitations is better-auth's GET /organization/list-user-invitations: an array of the pending
// invitations addressed to the caller's (verified) email, with organizationName. goauth also adds
// organizationSlug and the inviter.
func (h *OrgHandler) ListUserInvitations(ctx context.Context, input *ListUserInvitationsInput) (*humatypes.HumaRes[[]orgdtos.InvitationResponse], error) {
	// Step 1: Authenticate requesting user
	sessionResp, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	// Step 2: better-auth refuses client calls passing an email, and unverified session emails
	if input.Email != "" {
		return nil, humatypes.RespondErr(autherr.New(autherr.BadRequest, "User email cannot be passed for client side API calls.", http.StatusBadRequest))
	}
	// (sessions resolved from token claims carry no email; their verification state is unknown here)
	if sessionResp.User.Email != "" && !sessionResp.User.EmailVerified {
		return nil, humatypes.RespondErr(orgerrors.ErrEmailVerificationRequiredForInvitation)
	}

	// Step 3: Resolve user email from session user or fallback lookup
	email := sessionResp.User.Email
	if email == "" {
		email, err = h.Org.UserEmail(ctx, sessionResp.User.ID)
		if err != nil {
			return nil, humatypes.RespondErr(err)
		}
	}

	// Step 4: Fetch pending invitations for the user's email
	invs, err := h.Org.ListUserInvitations(ctx, email)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}

	// Step 5: Convert invitations with enriched org/inviter fields
	resps := make([]orgdtos.InvitationResponse, 0, len(invs))
	for i := range invs {
		resps = append(resps, *orgdtos.InvitationToResponse(&invs[i]))
	}
	return humatypes.MakeRes(resps, http.StatusOK), nil
}

// creatorRole returns the role organization creators get (OrgConfig.CreatorRole, default "owner").
func (h *OrgHandler) creatorRole() string {
	if r := h.Org.OrgConfig().CreatorRole; r != "" {
		return r
	}
	return orgmodels.OrgRoleOwner.Str()
}
