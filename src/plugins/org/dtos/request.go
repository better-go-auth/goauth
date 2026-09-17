package dtos

import "github.com/better-go-auth/goauth/src/plugins/org/models"

// ─── Org Request DTOs ────────────────────────────────────────────────────────

// CreateOrgInput matches better-auth POST /organization/create body.
type CreateOrgInput struct {
	Name     string  `json:"name"   validate:"required,min=1"`
	Slug     string  `json:"slug"   validate:"required,min=1,max=100"`
	Logo     *string `json:"logo"`
	Metadata *string `json:"metadata"`
}

// UpdateOrgInput matches better-auth POST /organization/update body.
type UpdateOrgInput struct {
	OrganizationID string  `json:"organizationId" validate:"required"`
	Name           *string `json:"name"`
	Slug           *string `json:"slug"`
	Logo           *string `json:"logo"`
	Metadata       *string `json:"metadata"`
}

// DeleteOrgInput for DELETE /organization/delete
type DeleteOrgInput struct {
	OrganizationID string `json:"organizationId" validate:"required"`
}

// InviteMemberInput matches better-auth POST /organization/invite-member body.
type InviteMemberInput struct {
	OrganizationID string               `json:"organizationId" validate:"required"`
	Email          string               `json:"email"          validate:"required,email"`
	Role           models.OrgMemberRole `json:"role"           validate:"required"`
}

// RemoveMemberInput matches better-auth POST /organization/remove-member body.
type RemoveMemberInput struct {
	OrganizationID string `json:"organizationId" validate:"required"`
	MemberID       string `json:"memberId"       validate:"required"`
}

// UpdateMemberRoleInput matches better-auth POST /organization/update-member-role body.
type UpdateMemberRoleInput struct {
	OrganizationID string               `json:"organizationId" validate:"required"`
	MemberID       string               `json:"memberId"       validate:"required"`
	Role           models.OrgMemberRole `json:"role"           validate:"required"`
}

// AcceptInvitationInput matches better-auth POST /organization/accept-invitation body.
type AcceptInvitationInput struct {
	InvitationID string `json:"invitationId" validate:"required"`
}

// SetActiveOrgInput matches better-auth POST /organization/set-active body.
type SetActiveOrgInput struct {
	OrganizationID *string `json:"organizationId"` // nil to unset active org
}
