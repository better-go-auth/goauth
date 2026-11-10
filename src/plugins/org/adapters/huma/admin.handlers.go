package humaorg

import (
	"context"
	"net/http"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/models/enums"
	orgdtos "github.com/better-go-auth/goauth/src/plugins/org/dtos"
	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
)

// ─── Admin Org Handlers ───────────────────────────────────────────────────────

// isSystemAdmin returns true when the authenticated session user has the system Admin role.
func isSystemAdmin(role string) bool {
	return enums.HasRole(role, enums.Admin.S())
}

// AdminApproveOrg approves a pending organization (system Admin only).
func (h *OrgHandler) AdminApproveOrg(ctx context.Context, input *AdminApproveOrgInput) (*humatypes.HumaRes[orgdtos.OrgResponse], error) {
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	if !isSystemAdmin(session.User.Role) {
		return nil, humatypes.RespondErr(autherr.ErrForbidden)
	}
	org, err := h.Org.AdminApproveOrg(ctx, input.Body.OrganizationID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeRes(*orgdtos.OrgToResponse(org), http.StatusOK), nil
}

// AdminBlockOrg suspends an organization (system Admin only).
func (h *OrgHandler) AdminBlockOrg(ctx context.Context, input *AdminBlockOrgInput) (*humatypes.HumaRes[orgdtos.OrgResponse], error) {
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	if !isSystemAdmin(session.User.Role) {
		return nil, humatypes.RespondErr(autherr.ErrForbidden)
	}
	org, err := h.Org.AdminBlockOrg(ctx, input.Body.OrganizationID, input.Body.Reason)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeRes(*orgdtos.OrgToResponse(org), http.StatusOK), nil
}

// AdminUnblockOrg re-activates a suspended or inactive organization (system Admin only).
func (h *OrgHandler) AdminUnblockOrg(ctx context.Context, input *AdminUnblockOrgInput) (*humatypes.HumaRes[orgdtos.OrgResponse], error) {
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	if !isSystemAdmin(session.User.Role) {
		return nil, humatypes.RespondErr(autherr.ErrForbidden)
	}
	org, err := h.Org.AdminUnblockOrg(ctx, input.Body.OrganizationID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeRes(*orgdtos.OrgToResponse(org), http.StatusOK), nil
}

// AdminListOrgsResp is the paginated response body for admin org listing.
type AdminListOrgsResp struct {
	Organizations []orgdtos.OrgResponse `json:"organizations"`
	Total         int64                 `json:"total"`
}

// AdminCreateOrg creates and immediately activates an organization (system Admin only).
func (h *OrgHandler) AdminCreateOrg(ctx context.Context, input *AdminCreateOrgInput) (*humatypes.HumaRes[orgdtos.OrgResponse], error) {
	// Step 1: Authenticate caller and verify system Admin role
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	if !isSystemAdmin(session.User.Role) {
		return nil, humatypes.RespondErr(autherr.ErrForbidden)
	}

	// Step 2: Create organization as active via admin service method
	org, err := h.Org.AdminCreateOrganization(ctx, session.User.ID, input.Body)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeRes(*orgdtos.OrgToResponse(org), http.StatusCreated), nil
}

// AdminGetOrg returns a single organization by ID (system Admin only).
func (h *OrgHandler) AdminGetOrg(ctx context.Context, input *AdminGetOrgInput) (*humatypes.HumaRes[orgdtos.OrgResponse], error) {
	// Step 1: Authenticate caller and verify system Admin role
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	if !isSystemAdmin(session.User.Role) {
		return nil, humatypes.RespondErr(autherr.ErrForbidden)
	}

	// Step 2: Fetch organization by ID
	org, err := h.Org.GetOrganization(ctx, input.OrganizationID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeRes(*orgdtos.OrgToResponse(org), http.StatusOK), nil
}

// AdminListOrgs returns all organizations with optional status and search filter (system Admin only).
func (h *OrgHandler) AdminListOrgs(ctx context.Context, input *AdminListOrgsInput) (*humatypes.HumaRes[AdminListOrgsResp], error) {
	// Step 1: Authenticate caller and verify system Admin role
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	if !isSystemAdmin(session.User.Role) {
		return nil, humatypes.RespondErr(autherr.ErrForbidden)
	}

	// Step 2: Parse optional status filter and search query
	var statusFilter *orgmodels.OrgStatus
	if input.Status != "" {
		s := orgmodels.OrgStatus(input.Status)
		statusFilter = &s
	}

	query := input.Q
	if query == "" {
		query = input.Search
	}

	limit := input.Limit
	if limit <= 0 {
		limit = 50
	}
	pagi := orgmodels.Pagination{Limit: limit, Offset: input.Offset, SortBy: "createdAt", SortDir: "desc"}

	// Step 3: Query organizations matching status and search query
	orgs, total, err := h.Org.AdminSearchOrganizations(ctx, statusFilter, query, pagi)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	resps := make([]orgdtos.OrgResponse, 0, len(orgs))
	for i := range orgs {
		resps = append(resps, *orgdtos.OrgToResponse(&orgs[i]))
	}
	return humatypes.MakeRes(AdminListOrgsResp{Organizations: resps, Total: total}, http.StatusOK), nil
}
