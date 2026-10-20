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

// InvitationInput matches better-auth POST /organization/accept-invitation body.
type InvitationInput struct {
	InvitationID string `json:"invitationId" validate:"required"`
}

// SetActiveOrgInput matches better-auth POST /organization/set-active body.
type SetActiveOrgInput struct {
	OrganizationID *string `json:"organizationId"` // nil to unset active org
}

// ─── Admin Request DTOs ──────────────────────────────────────────────────────

// AdminOrgIDInput is used for admin actions that only need an org ID.
type AdminOrgIDInput struct {
	OrganizationID string `json:"organizationId" validate:"required"`
}

// AdminBlockOrgInput is used for blocking/suspending an organization.
type AdminBlockOrgInput struct {
	OrganizationID string `json:"organizationId" validate:"required"`
	Reason         string `json:"reason"`
}

// ─── Team Request DTOs ───────────────────────────────────────────────────────

// CreateTeamInput matches better-auth POST /organization/team/create body.
type CreateTeamInput struct {
	OrganizationID string `json:"organizationId" validate:"required"`
	Name           string `json:"name"           validate:"required,min=1"`
}

// UpdateTeamInput matches better-auth POST /organization/team/update body.
type UpdateTeamInput struct {
	TeamID         string `json:"teamId"         validate:"required"`
	Name           string `json:"name"           validate:"required,min=1"`
	OrganizationID string `json:"organizationId"`
}

// DeleteTeamInput matches better-auth POST /organization/team/delete body.
type DeleteTeamInput struct {
	TeamID         string `json:"teamId"         validate:"required"`
	OrganizationID string `json:"organizationId"`
}

// ListTeamsInput matches better-auth GET /organization/team/list query.
type ListTeamsInput struct {
	OrganizationID string `json:"organizationId"`
}

// AddTeamMemberInput matches better-auth POST /organization/team/add-member body.
type AddTeamMemberInput struct {
	TeamID         string `json:"teamId"         validate:"required"`
	UserID         string `json:"userId"         validate:"required"`
	OrganizationID string `json:"organizationId"`
}

// RemoveTeamMemberInput matches better-auth POST /organization/team/remove-member body.
type RemoveTeamMemberInput struct {
	TeamID         string `json:"teamId"         validate:"required"`
	UserID         string `json:"userId"         validate:"required"`
	OrganizationID string `json:"organizationId"`
}

// SetActiveTeamInput matches better-auth POST /organization/set-active-team body.
type SetActiveTeamInput struct {
	TeamID *string `json:"teamId"` // nil to unset active team
}

// ─── Dynamic Access Control DTOs ─────────────────────────────────────────────

// CreateOrgRoleInput represents the payload to create a dynamic organization role.
type CreateOrgRoleInput struct {
	OrganizationID string `json:"organizationId" validate:"required"`
	Role           string `json:"role"           validate:"required,min=1"`
	Permission     string `json:"permission"     validate:"required"` // JSON document
}

// UpdateOrgRoleInput represents the payload to update a dynamic organization role.
type UpdateOrgRoleInput struct {
	OrganizationID string `json:"organizationId" validate:"required"`
	Role           string `json:"role"           validate:"required,min=1"`
	Permission     string `json:"permission"     validate:"required"` // JSON document
}

// DeleteOrgRoleInput represents the payload to delete a dynamic organization role.
type DeleteOrgRoleInput struct {
	OrganizationID string `json:"organizationId" validate:"required"`
	Role           string `json:"role"           validate:"required,min=1"`
}

