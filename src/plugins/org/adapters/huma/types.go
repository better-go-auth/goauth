// Package humaorg provides the Huma HTTP adapter for the org domain.
package humaorg

import (
	orgdtos "github.com/better-go-auth/goauth/src/plugins/org/dtos"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
)

// ─── Org Inputs ───────────────────────────────────────────────────────────────

type CreateOrgInput = humatypes.HumaReqBody[orgdtos.CreateOrgInput]

type GetOrgInput struct {
	humatypes.AuthHeaders
	OrganizationID string `query:"organizationId" doc:"Organization ID"`
}

type UpdateOrgInput = humatypes.HumaReqBody[orgdtos.UpdateOrgInput]
type DeleteOrgInput = humatypes.HumaReqBody[orgdtos.DeleteOrgInput]
type ListOrgsInput struct{ humatypes.AuthHeaders }
type SetActiveOrgInput = humatypes.HumaReqBody[orgdtos.SetActiveOrgInput]

// ─── Invitation Inputs ────────────────────────────────────────────────────────

type InviteMemberInput = humatypes.HumaReqBody[orgdtos.InviteMemberInput]

type GetInvitationInput struct {
	humatypes.AuthHeaders
	InvitationID string `query:"invitationId" doc:"Invitation ID"`
}

type AcceptInvitationInput = humatypes.HumaReqBody[orgdtos.AcceptInvitationInput]
type RejectInvitationInput = humatypes.HumaReqBody[orgdtos.AcceptInvitationInput]
type CancelInvitationInput = humatypes.HumaReqBody[orgdtos.AcceptInvitationInput]

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

type UpdateMemberRoleInput = humatypes.HumaReqBody[orgdtos.UpdateMemberRoleInput]
type RemoveMemberInput = humatypes.HumaReqBody[orgdtos.RemoveMemberInput]
