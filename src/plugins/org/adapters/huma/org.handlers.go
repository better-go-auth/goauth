package humaorg

import (
	"context"
	"net/http"

	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/models/dtos"
	orgdtos "github.com/better-go-auth/goauth/src/plugins/org/dtos"
	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
)

// ─── Org ──────────────────────────────────────────────────────────────────────

func (h *OrgHandler) CreateOrg(ctx context.Context, input *CreateOrgInput) (*humatypes.HumaRes[orgdtos.OrgResponse], error) {
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
	return humatypes.MakeRes(*orgdtos.OrgToResponse(org), http.StatusCreated), nil
}

func (h *OrgHandler) GetOrg(ctx context.Context, input *GetOrgInput) (*humatypes.HumaRes[orgdtos.OrgResponse], error) {
	// Step 1: Resolve organization ID from slug if only organizationSlug was provided
	targetOrgID := input.OrganizationID
	if targetOrgID == "" && input.OrganizationSlug != "" {
		if orgBySlug, err := h.Org.GetOrganizationBySlug(ctx, input.OrganizationSlug); err == nil && orgBySlug != nil {
			targetOrgID = orgBySlug.ID
		}
	}
	// Step 2: Verify membership and fetch organization
	_, orgID, err := h.RequireOrgOp(ctx, input.AuthHeaders, targetOrgID, OrGetOrg)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	org, err := h.Org.GetOrganization(ctx, orgID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeRes(*orgdtos.OrgToResponse(org), http.StatusOK), nil
}

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

func (h *OrgHandler) DeleteOrg(ctx context.Context, input *DeleteOrgInput) (*humatypes.SuccessOutput, error) {
	session, _, err := h.RequireOrgOp(ctx, input.AuthHeaders, input.Body.OrganizationID, OrDeleteOrg)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	if err := h.Org.DeleteOrganization(ctx, input.Body.OrganizationID, session.User.ID); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.SuccessRes(http.StatusOK), nil
}

func (h *OrgHandler) ListOrgs(ctx context.Context, input *ListOrgsInput) (*humatypes.HumaRes[struct {
	Organizations []orgdtos.OrgResponse `json:"organizations"`
}], error) {
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	orgs, err := h.Org.ListOrganizations(ctx, session.User.ID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	resps := make([]orgdtos.OrgResponse, 0, len(orgs))
	for i := range orgs {
		resps = append(resps, *orgdtos.OrgToResponse(&orgs[i]))
	}
	return humatypes.MakeRes(struct {
		Organizations []orgdtos.OrgResponse `json:"organizations"`
	}{Organizations: resps}, http.StatusOK), nil
}

func (h *OrgHandler) SetActiveOrg(ctx context.Context, input *SetActiveOrgInput) (*humatypes.HumaRes[*dtos.SessionWithUser], error) {
	// Step 1: Authenticate caller session
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	// Step 2: Resolve organization ID from slug if organizationId was not supplied
	orgID := input.Body.OrganizationID
	if (orgID == nil || *orgID == "") && input.Body.OrganizationSlug != nil && *input.Body.OrganizationSlug != "" {
		orgBySlug, err := h.Org.GetOrganizationBySlug(ctx, *input.Body.OrganizationSlug)
		if err != nil {
			return nil, humatypes.RespondErr(err)
		}
		orgID = &orgBySlug.ID
	}
	// Step 3: Verify membership if setting an active org
	if orgID != nil && *orgID != "" {
		if _, _, err := h.RequireOrgOp(ctx, input.AuthHeaders, *orgID, OrSetActiveOrg); err != nil {
			return nil, humatypes.RespondErr(err)
		}
	}
	// Step 4: Update active organization on session
	resp, err := h.Org.SetActiveOrganization(ctx, session.Session.ID, orgID, session.User.ID, session.User.Role)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeRes(resp, http.StatusOK), nil
}
