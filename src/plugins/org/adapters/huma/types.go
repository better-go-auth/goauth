// Package humaorg provides the Huma HTTP adapter for the org domain.
package humaorg

import (
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	orgdtos "github.com/better-go-auth/goauth/src/plugins/org/dtos"
)

// ─── Org Inputs ───────────────────────────────────────────────────────────────

type CreateOrgInput = humatypes.HumaReqBody[orgdtos.CreateOrgInput]

type GetOrgInput struct {
	humatypes.AuthHeaders
	OrganizationID string `query:"organizationId" doc:"Organization ID"`
}

type (
	UpdateOrgInput    = humatypes.HumaReqBody[orgdtos.UpdateOrgInput]
	DeleteOrgInput    = humatypes.HumaReqBody[orgdtos.DeleteOrgInput]
	ListOrgsInput     struct{ humatypes.AuthHeaders }
	SetActiveOrgInput = humatypes.HumaReqBody[orgdtos.SetActiveOrgInput]
)

// ─── Invitation Inputs ────────────────────────────────────────────────────────

type InviteMemberInput = humatypes.HumaReqBody[orgdtos.InviteMemberInput]

type GetInvitationInput struct {
	humatypes.AuthHeaders
	InvitationID string `query:"invitationId" doc:"Invitation ID"`
}

type (
	HumaInvitationInput   = humatypes.HumaReqBody[orgdtos.InvitationInput]
	// RejectInvitationInput = humatypes.HumaReqBody[orgdtos.InvitationInput]
	// CancelInvitationInput = humatypes.HumaReqBody[orgdtos.InvitationInput]
)

type ListInvitationsInput struct {
	humatypes.AuthHeaders
	OrganizationID string `query:"organizationId" doc:"Organization ID"`
}

// ─── Member Inputs ────────────────────────────────────────────────────────────

type GetMemberInput struct {
	humatypes.AuthHeaders
	OrganizationID string `query:"organizationId" doc:"Organization ID"`
	UserID         string `query:"userId,omitempty" doc:"User ID (defaults to current authenticated user)"`
}

type ListMembersInput struct {
	humatypes.AuthHeaders
	OrganizationID string `query:"organizationId" doc:"Organization ID"`
}

type (
	UpdateMemberRoleInput = humatypes.HumaReqBody[orgdtos.UpdateMemberRoleInput]
	RemoveMemberInput     = humatypes.HumaReqBody[orgdtos.RemoveMemberInput]
)

// ─── Admin Inputs ─────────────────────────────────────────────────────────────

type (
	AdminApproveOrgInput = humatypes.HumaReqBody[orgdtos.AdminOrgIDInput]
	AdminBlockOrgInput   = humatypes.HumaReqBody[orgdtos.AdminBlockOrgInput]
	AdminUnblockOrgInput = humatypes.HumaReqBody[orgdtos.AdminOrgIDInput]
)

type AdminListOrgsInput struct {
	humatypes.AuthHeaders
	Status string `query:"status,omitempty" doc:"Filter by org status: active, pending, inactive, suspended"`
	Limit  int    `query:"limit,omitempty" doc:"Page size (default 50)"`
	Offset int    `query:"offset,omitempty" doc:"Page offset"`
}

