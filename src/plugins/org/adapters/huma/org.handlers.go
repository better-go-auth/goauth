package humaorg

import (
	"context"
	"net/http"

	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/models"
	orgdtos "github.com/better-go-auth/goauth/src/plugins/org/dtos"
)

// ─── Org ──────────────────────────────────────────────────────────────────────

func (h *OrgHandler) CreateOrg(ctx context.Context, input *CreateOrgInput) (*humatypes.HumaRes[orgdtos.OrgResponse], error) {
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	org, err := h.Org.CreateOrganization(ctx, session.User.ID, input.Body)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeRes(*orgdtos.OrgToResponse(org), http.StatusCreated), nil
}

func (h *OrgHandler) GetOrg(ctx context.Context, input *GetOrgInput) (*humatypes.HumaRes[orgdtos.OrgResponse], error) {
	_, orgID, err := h.RequireOrgMember(ctx, input.AuthHeaders, input.OrganizationID, rolesFor(OrGetOrg)...)
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
	session, _, err := h.RequireOrgMember(ctx, input.AuthHeaders, input.Body.OrganizationID, rolesFor(OrUpdateOrg)...)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	org, err := h.Org.UpdateOrganization(ctx, input.Body.OrganizationID, input.Body, session.User.ID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeRes(*orgdtos.OrgToResponse(org), http.StatusOK), nil
}

func (h *OrgHandler) DeleteOrg(ctx context.Context, input *DeleteOrgInput) (*humatypes.SuccessOutput, error) {
	session, _, err := h.RequireOrgMember(ctx, input.AuthHeaders, input.Body.OrganizationID, rolesFor(OrDeleteOrg)...)
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

func (h *OrgHandler) SetActiveOrg(ctx context.Context, input *SetActiveOrgInput) (*humatypes.HumaRes[*models.AuthTokens], error) {
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	if id := input.Body.OrganizationID; id != nil && *id != "" {
		if _, _, err := h.RequireOrgMember(ctx, input.AuthHeaders, *id, rolesFor(OrSetActiveOrg)...); err != nil {
			return nil, humatypes.RespondErr(err)
		}
	}
	resp, err := h.Org.SetActiveOrganization(ctx, session.Session.ID, input.Body.OrganizationID, session.User.ID, session.User.Role)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeRes(resp, http.StatusOK), nil
}
