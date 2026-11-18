package humaorg

import (
	"context"
	"net/http"

	humatypes "github.com/better-go-auth/goauth/src/common/types"
	orgdtos "github.com/better-go-auth/goauth/src/plugins/org/dtos"
	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
	orgerrors "github.com/better-go-auth/goauth/src/plugins/org/org-errors"
)

// ─── Org ──────────────────────────────────────────────────────────────────────

// CreateOrg is better-auth's POST /organization/create: 200 with the organization and `members: [creator]`.
func (h *OrgHandler) CreateOrg(ctx context.Context, input *CreateOrgInput) (*humatypes.HumaRes[orgdtos.CreatedOrgResponse], error) {
	// Step 1: Authenticate caller session
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	// Step 2: Create organization in service layer
	org, err := h.Org.CreateOrganization(ctx, session.User.ID, input.Body)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	// Step 3: Set newly created active organization on session unless caller opted out
	if org.Status == orgmodels.OrgStatusActive && !input.Body.KeepCurrentActiveOrganization && session.Session.ID != "" {
		_, _ = h.Org.SetActiveOrganization(ctx, session.Session.ID, &org.ID, session.User.ID, session.User.Role)
	}
	// Step 4: better-auth returns the organization with the creator's membership (raw member row)
	out := orgdtos.CreatedOrgResponse{OrgResponse: *orgdtos.OrgToResponse(org), Members: []orgdtos.MemberResponse{}}
	if member, mErr := h.Org.GetMember(ctx, org.ID, session.User.ID); mErr == nil && member != nil {
		out.Members = append(out.Members, *orgdtos.MemberWithoutUser(member))
	}
	return humatypes.MakeRes(out, http.StatusOK), nil
}

// GetOrg is better-auth's GET /organization/get-full-organization: the organization (by organizationSlug,
// organizationId or the active one) with members, invitations and teams; null when none is selected.
func (h *OrgHandler) GetOrg(ctx context.Context, input *GetOrgInput) (*humatypes.HumaRes[*orgdtos.FullOrgResponse], error) {
	// Step 1: Authenticate caller session
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	// Step 2: Resolve the organization: slug, then ID, then the active organization (none → null)
	var org *orgmodels.Organization
	switch {
	case input.OrganizationSlug != "":
		org, err = h.Org.GetOrganizationBySlug(ctx, input.OrganizationSlug)
	case input.OrganizationID != "":
		org, err = h.Org.GetOrganization(ctx, input.OrganizationID)
	case session.Session.ActiveOrganizationID != nil && *session.Session.ActiveOrganizationID != "":
		org, err = h.Org.GetOrganization(ctx, *session.Session.ActiveOrganizationID)
	default:
		return humatypes.MakeRes[*orgdtos.FullOrgResponse](nil, http.StatusOK), nil
	}
	if err != nil || org == nil {
		return nil, humatypes.RespondErr(orgerrors.ErrOrgNotFound)
	}
	// Step 3: Verify membership and the read permission of the operation table
	if _, _, err := h.RequireOrgOp(ctx, input.AuthHeaders, org.ID, OrGetOrg); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	// Step 4: Members (with users), invitations and teams
	full, err := h.fullOrganization(ctx, org, session.User.ID, input.MembersLimit)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeRes(full, http.StatusOK), nil
}

// fullOrganization builds better-auth's findFullOrganization result.
func (h *OrgHandler) fullOrganization(ctx context.Context, org *orgmodels.Organization, userID string, membersLimit int) (*orgdtos.FullOrgResponse, error) {
	// Step 1: members with their users (limit: membersLimit, else the membership limit, else 100)
	limit := membersLimit
	if limit <= 0 {
		limit = 100
		if l := h.Org.OrgConfig().MembershipLimit; l != nil && *l > 0 {
			limit = *l
		}
	}
	members, _, err := h.Org.ListMembers(ctx, org.ID, orgmodels.Pagination{Limit: limit, SortBy: "createdAt", SortDir: "asc"})
	if err != nil {
		return nil, err
	}
	full := &orgdtos.FullOrgResponse{
		OrgResponse: *orgdtos.OrgToResponse(org),
		Members:     make([]orgdtos.MemberResponse, 0, len(members)),
		Invitations: []orgdtos.InvitationResponse{},
	}
	for i := range members {
		full.Members = append(full.Members, *orgdtos.MemberToResponse(&members[i]))
	}
	// Step 2: every invitation of the organization (all statuses, as better-auth's join)
	invs, _, err := h.Org.ListInvitations(ctx, org.ID, orgmodels.Pagination{Limit: 1000})
	if err != nil {
		return nil, err
	}
	for i := range invs {
		full.Invitations = append(full.Invitations, *invitationRow(&invs[i]))
	}
	// Step 3: teams, only when the teams feature is enabled
	if h.Org.TeamsEnabled() {
		list := []orgdtos.TeamResponse{}
		teams, _, err := h.Org.ListTeams(ctx, org.ID, userID, orgmodels.Pagination{Limit: 1000})
		if err == nil {
			for i := range teams {
				list = append(list, *orgdtos.TeamToResponse(&teams[i]))
			}
		}
		full.Teams = &list
	}
	return full, nil
}

// UpdateOrg is better-auth's POST /organization/update: the updated organization.
func (h *OrgHandler) UpdateOrg(ctx context.Context, input *UpdateOrgInput) (*humatypes.HumaRes[orgdtos.OrgResponse], error) {
	// Step 1: Verify membership (falling back to session active org if organizationId omitted)
	session, orgID, err := h.RequireOrgOp(ctx, input.AuthHeaders, input.Body.OrganizationID, OrUpdateOrg)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	// Step 2: Update organization via service layer
	org, err := h.Org.UpdateOrganization(ctx, orgID, input.Body, session.User.ID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeRes(*orgdtos.OrgToResponse(org), http.StatusOK), nil
}

// CheckSlug is better-auth's POST /organization/check-slug: {status: true}, or 400
// ORGANIZATION_SLUG_ALREADY_TAKEN when the slug is used.
func (h *OrgHandler) CheckSlug(ctx context.Context, input *CheckSlugInput) (*humatypes.HumaRes[struct {
	Status bool `json:"status"`
}], error) {
	// Step 1: Authenticate caller session
	if _, err := h.Authenticate(ctx, input.AuthHeaders); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	// Step 2: Check slug availability
	ok, err := h.Org.CheckSlug(ctx, input.Body.Slug)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeRes(struct {
		Status bool `json:"status"`
	}{Status: ok}, http.StatusOK), nil
}

// DeleteOrg is better-auth's POST /organization/delete: the deleted organization.
func (h *OrgHandler) DeleteOrg(ctx context.Context, input *DeleteOrgInput) (*humatypes.HumaRes[orgdtos.OrgResponse], error) {
	// Step 1: deletion may be disabled (better-auth checks it first: 404 ORGANIZATION_DELETION_DISABLED)
	if h.Org.OrgConfig().DisableOrganizationDeletion {
		return nil, humatypes.RespondErr(orgerrors.ErrOrganizationDeletionDisabled)
	}
	if input.Body.OrganizationID == "" {
		return nil, humatypes.RespondErr(orgerrors.ErrOrgNotFound)
	}
	// Step 2: membership and organization:delete permission
	session, _, err := h.RequireOrgOp(ctx, input.AuthHeaders, input.Body.OrganizationID, OrDeleteOrg)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	// Step 3: load the organization (returned to the client), then delete it
	org, err := h.Org.GetOrganization(ctx, input.Body.OrganizationID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	if err := h.Org.DeleteOrganization(ctx, input.Body.OrganizationID, session.User.ID); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeRes(*orgdtos.OrgToResponse(org), http.StatusOK), nil
}

// ListOrgs is better-auth's GET /organization/list: an array of the user's organizations.
func (h *OrgHandler) ListOrgs(ctx context.Context, input *ListOrgsInput) (*humatypes.HumaRes[[]orgdtos.OrgResponse], error) {
	// Step 1: Authenticate caller session
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	// Step 2: the organizations the user is a member of
	orgs, err := h.Org.ListOrganizations(ctx, session.User.ID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	resps := make([]orgdtos.OrgResponse, 0, len(orgs))
	for i := range orgs {
		resps = append(resps, *orgdtos.OrgToResponse(&orgs[i]))
	}
	return humatypes.MakeRes(resps, http.StatusOK), nil
}

// SetActiveOrg is better-auth's POST /organization/set-active: the now active organization, or null when
// organizationId is null (or nothing was active).
func (h *OrgHandler) SetActiveOrg(ctx context.Context, input *SetActiveOrgInput) (*humatypes.HumaRes[*orgdtos.OrgResponse], error) {
	// Step 1: Authenticate caller session
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	active := session.Session.ActiveOrganizationID
	// Step 2: organizationId: null unsets the active organization
	if input.Body.OrganizationIDNull {
		if active == nil || *active == "" {
			return humatypes.MakeRes[*orgdtos.OrgResponse](nil, http.StatusOK), nil
		}
		if _, err := h.Org.SetActiveOrganization(ctx, session.Session.ID, nil, session.User.ID, session.User.Role); err != nil {
			return nil, humatypes.RespondErr(err)
		}
		return humatypes.MakeRes[*orgdtos.OrgResponse](nil, http.StatusOK), nil
	}
	// Step 3: Resolve the organization: ID, else slug, else the currently active one (none → null)
	var orgID string
	switch {
	case input.Body.OrganizationID != nil && *input.Body.OrganizationID != "":
		orgID = *input.Body.OrganizationID
	case input.Body.OrganizationSlug != nil && *input.Body.OrganizationSlug != "":
		orgBySlug, err := h.Org.GetOrganizationBySlug(ctx, *input.Body.OrganizationSlug)
		if err != nil {
			return nil, humatypes.RespondErr(orgerrors.ErrOrgNotFound)
		}
		orgID = orgBySlug.ID
	case active != nil && *active != "":
		orgID = *active
	default:
		return humatypes.MakeRes[*orgdtos.OrgResponse](nil, http.StatusOK), nil
	}
	// Step 4: Verify membership (better-auth also clears the active organization of a non-member)
	if _, _, err := h.RequireOrgOp(ctx, input.AuthHeaders, orgID, OrSetActiveOrg); err != nil {
		if active != nil && *active != "" {
			_, _ = h.Org.SetActiveOrganization(ctx, session.Session.ID, nil, session.User.ID, session.User.Role)
		}
		return nil, humatypes.RespondErr(err)
	}
	// Step 5: Update active organization on session and return the organization
	if _, err := h.Org.SetActiveOrganization(ctx, session.Session.ID, &orgID, session.User.ID, session.User.Role); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	org, err := h.Org.GetOrganization(ctx, orgID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeRes(orgdtos.OrgToResponse(org), http.StatusOK), nil
}
