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
	OrganizationID   string `query:"organizationId,omitempty" doc:"Organization ID"`
	OrganizationSlug string `query:"organizationSlug,omitempty" doc:"Organization Slug"`
	MembersLimit     int    `query:"membersLimit,omitempty" doc:"Maximum number of members to return (default: the membership limit)"`
}

type (
	UpdateOrgInput    = humatypes.HumaReqBody[orgdtos.UpdateOrgInput]
	CheckSlugInput    = humatypes.HumaReqBody[orgdtos.CheckSlugInput]
	DeleteOrgInput    = humatypes.HumaReqBody[orgdtos.DeleteOrgInput]
	ListOrgsInput     struct{ humatypes.AuthHeaders }
	SetActiveOrgInput = humatypes.HumaReqBody[orgdtos.SetActiveOrgInput]
)

// ─── Invitation Inputs ────────────────────────────────────────────────────────

type InviteMemberInput = humatypes.HumaReqBody[orgdtos.InviteMemberInput]

type GetInvitationInput struct {
	humatypes.AuthHeaders
	InvitationID string `query:"invitationId,omitempty" doc:"Invitation ID"`
	ID           string `query:"id,omitempty" doc:"Invitation ID (better-auth client query param)"`
}

type (
	HumaInvitationInput = humatypes.HumaReqBody[orgdtos.InvitationInput]
	// RejectInvitationInput = humatypes.HumaReqBody[orgdtos.InvitationInput]
	// CancelInvitationInput = humatypes.HumaReqBody[orgdtos.InvitationInput]
)

type ListInvitationsInput struct {
	humatypes.AuthHeaders
	OrganizationID string `query:"organizationId" doc:"Organization ID"`
}

type ListUserInvitationsInput struct {
	humatypes.AuthHeaders
	// Email is better-auth's server-only email query; client calls passing it are rejected.
	Email string `query:"email,omitempty" doc:"Server-side only; rejected for client requests"`
}

// ─── Member Inputs ────────────────────────────────────────────────────────────

type GetMemberInput struct {
	humatypes.AuthHeaders
	OrganizationID string `query:"organizationId" doc:"Organization ID"`
	UserID         string `query:"userId,omitempty" doc:"User ID (defaults to current authenticated user)"`
}

type ListMembersInput struct {
	humatypes.AuthHeaders
	OrganizationID   string `query:"organizationId" doc:"Organization ID"`
	OrganizationSlug string `query:"organizationSlug,omitempty" doc:"Organization slug (wins over organizationId)"`
	Limit            int    `query:"limit,omitempty" doc:"Number of members to return (default: the membership limit, else 100)"`
	Offset           int    `query:"offset,omitempty" doc:"Offset to start from"`
	SortBy           string `query:"sortBy,omitempty" doc:"Field to sort by"`
	SortDirection    string `query:"sortDirection,omitempty" enum:"asc,desc" doc:"Sort direction"`
}

// GetActiveMemberInput is better-auth's GET /organization/get-active-member (no parameters).
type GetActiveMemberInput struct {
	humatypes.AuthHeaders
}

// GetActiveMemberRoleInput is better-auth's GET /organization/get-active-member-role query.
type GetActiveMemberRoleInput struct {
	humatypes.AuthHeaders
	UserID           string `query:"userId,omitempty" doc:"User whose role to return (default: the caller)"`
	OrganizationID   string `query:"organizationId,omitempty" doc:"Organization ID (default: the active organization)"`
	OrganizationSlug string `query:"organizationSlug,omitempty" doc:"Organization slug (wins over organizationId)"`
}

// ListUserTeamsInput is better-auth's GET /organization/list-user-teams (no parameters).
type ListUserTeamsInput struct {
	humatypes.AuthHeaders
}

type (
	UpdateMemberRoleInput = humatypes.HumaReqBody[orgdtos.UpdateMemberRoleInput]
	RemoveMemberInput     = humatypes.HumaReqBody[orgdtos.RemoveMemberInput]
	LeaveOrgInput         = humatypes.HumaReqBody[orgdtos.LeaveOrgInput]
)

// ─── Admin Inputs ─────────────────────────────────────────────────────────────

type (
	AdminCreateOrgInput  = humatypes.HumaReqBody[orgdtos.AdminCreateOrgInput]
	AdminApproveOrgInput = humatypes.HumaReqBody[orgdtos.AdminOrgIDInput]
	AdminBlockOrgInput   = humatypes.HumaReqBody[orgdtos.AdminBlockOrgInput]
	AdminUnblockOrgInput = humatypes.HumaReqBody[orgdtos.AdminOrgIDInput]
)

type AdminGetOrgInput struct {
	humatypes.AuthHeaders
	OrganizationID string `query:"organizationId" doc:"Organization ID"`
}

type AdminListOrgsInput struct {
	humatypes.AuthHeaders
	Status string `query:"status,omitempty" doc:"Filter by org status: active, pending, inactive, suspended"`
	Q      string `query:"q,omitempty" doc:"Case-insensitive search on organization name or slug"`
	Search string `query:"_q,omitempty" doc:"Alias for q search query"`
	Limit  int    `query:"limit,omitempty" doc:"Page size (default 50)"`
	Offset int    `query:"offset,omitempty" doc:"Page offset"`
}
