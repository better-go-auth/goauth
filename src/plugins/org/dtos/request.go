package dtos

import "github.com/better-go-auth/goauth/src/plugins/org/models"

// ─── Org Request DTOs ────────────────────────────────────────────────────────

// CreateOrgInput matches better-auth POST /organization/create body.
type CreateOrgInput struct {
	Name                          string  `json:"name"                          validate:"required,min=1"`
	Slug                          string  `json:"slug"                          validate:"required,min=1,max=100"`
	Logo                          *string `json:"logo,omitempty"`
	Metadata                      *string `json:"metadata,omitempty"`
	OrgType                       *string `json:"orgType,omitempty"`
	KeepCurrentActiveOrganization bool    `json:"keepCurrentActiveOrganization,omitempty"`
}

// UpdateOrgData holds nested fields sent by official better-auth/client organization.update.
type UpdateOrgData struct {
	Name     *string `json:"name,omitempty"`
	Slug     *string `json:"slug,omitempty"`
	Logo     *string `json:"logo,omitempty"`
	Metadata *string `json:"metadata,omitempty"`
	OrgType  *string `json:"orgType,omitempty"`
}

// UpdateOrgInput matches better-auth POST /organization/update body (both flat and nested `data` formats).
type UpdateOrgInput struct {
	OrganizationID string         `json:"organizationId,omitempty"`
	Name           *string        `json:"name,omitempty"`
	Slug           *string        `json:"slug,omitempty"`
	Logo           *string        `json:"logo,omitempty"`
	Metadata       *string        `json:"metadata,omitempty"`
	OrgType        *string        `json:"orgType,omitempty"`
	Data           *UpdateOrgData `json:"data,omitempty"`
}

// CheckSlugInput matches better-auth POST /organization/check-slug body.
type CheckSlugInput struct {
	Slug string `json:"slug" validate:"required,min=1"`
}

// DeleteOrgInput for DELETE/POST /organization/delete.
type DeleteOrgInput struct {
	OrganizationID string `json:"organizationId" validate:"required"`
}

// InviteMemberInput matches better-auth POST /organization/invite-member body.
type InviteMemberInput struct {
	OrganizationID string               `json:"organizationId,omitempty"`
	Email          string               `json:"email"          validate:"required,email"`
	Role           models.OrgMemberRole `json:"role"           validate:"required"`
	TeamID         *string              `json:"teamId,omitempty"`
}

// RemoveMemberInput matches better-auth POST /organization/remove-member body.
type RemoveMemberInput struct {
	OrganizationID  string `json:"organizationId,omitempty"`
	MemberID        string `json:"memberId,omitempty"`
	MemberIDOrEmail string `json:"memberIdOrEmail,omitempty"`
}

// UpdateMemberRoleInput matches better-auth POST /organization/update-member-role body.
type UpdateMemberRoleInput struct {
	OrganizationID string               `json:"organizationId,omitempty"`
	MemberID       string               `json:"memberId"       validate:"required"`
	Role           models.OrgMemberRole `json:"role"           validate:"required"`
}

// InvitationInput matches better-auth POST /organization/accept-invitation body.
type InvitationInput struct {
	InvitationID string `json:"invitationId" validate:"required"`
}

// SetActiveOrgInput matches better-auth POST /organization/set-active body.
type SetActiveOrgInput struct {
	OrganizationID   *string `json:"organizationId,omitempty"`   // nil to unset active org
	OrganizationSlug *string `json:"organizationSlug,omitempty"` // optional slug fallback
}

// LeaveOrgInput matches better-auth POST /organization/leave body.
type LeaveOrgInput struct {
	OrganizationID string `json:"organizationId" validate:"required"`
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

// AdminCreateOrgInput allows a system administrator to create an active organization immediately.
type AdminCreateOrgInput struct {
	CreateOrgInput
	OwnerUserID string `json:"ownerUserId,omitempty"`
}

// ─── Team Request DTOs ───────────────────────────────────────────────────────

// CreateTeamInput matches better-auth POST /organization/create-team and /organization/team/create body.
type CreateTeamInput struct {
	OrganizationID string `json:"organizationId,omitempty"`
	Name           string `json:"name"           validate:"required,min=1"`
}

// UpdateTeamData holds nested fields sent by official better-auth/client organization.updateTeam.
type UpdateTeamData struct {
	Name string `json:"name,omitempty"`
}

// UpdateTeamInput matches better-auth POST /organization/update-team and /organization/team/update body.
type UpdateTeamInput struct {
	TeamID         string          `json:"teamId"         validate:"required"`
	Name           string          `json:"name,omitempty"`
	OrganizationID string          `json:"organizationId,omitempty"`
	Data           *UpdateTeamData `json:"data,omitempty"`
}

// DeleteTeamInput matches better-auth POST /organization/remove-team and /organization/team/delete body.
type DeleteTeamInput struct {
	TeamID         string `json:"teamId"         validate:"required"`
	OrganizationID string `json:"organizationId,omitempty"`
}

// ListTeamsInput matches better-auth GET /organization/list-teams query.
type ListTeamsInput struct {
	OrganizationID string `json:"organizationId"`
}

// AddTeamMemberInput matches better-auth POST /organization/add-team-member body.
type AddTeamMemberInput struct {
	TeamID         string `json:"teamId"         validate:"required"`
	UserID         string `json:"userId"         validate:"required"`
	OrganizationID string `json:"organizationId,omitempty"`
}

// RemoveTeamMemberInput matches better-auth POST /organization/remove-team-member body.
type RemoveTeamMemberInput struct {
	TeamID         string `json:"teamId"         validate:"required"`
	UserID         string `json:"userId"         validate:"required"`
	OrganizationID string `json:"organizationId,omitempty"`
}

// SetActiveTeamInput matches better-auth POST /organization/set-active-team body.
type SetActiveTeamInput struct {
	TeamID *string `json:"teamId,omitempty"` // nil to unset active team
}

// ─── Dynamic Access Control DTOs ─────────────────────────────────────────────

// CreateOrgRoleInput represents the payload to create a dynamic organization role.
type CreateOrgRoleInput struct {
	OrganizationID string            `json:"organizationId" validate:"required"`
	Role           string            `json:"role"           validate:"required,min=1"`
	Permission     models.Permission `json:"permission,omitempty"` // JSON map: e.g. {"project": ["read"]}
	Ops            models.Operations `json:"ops,omitempty"`        // List of allowed operation IDs
}

// UpdateOrgRoleInput represents the payload to update a dynamic organization role.
type UpdateOrgRoleInput struct {
	OrganizationID string            `json:"organizationId" validate:"required"`
	Role           string            `json:"role"           validate:"required,min=1"`
	Permission     models.Permission `json:"permission,omitempty"` // JSON map: e.g. {"project": ["read"]}
	Ops            models.Operations `json:"ops,omitempty"`        // List of allowed operation IDs
}

// DeleteOrgRoleInput represents the payload to delete a dynamic organization role.
type DeleteOrgRoleInput struct {
	OrganizationID string `json:"organizationId" validate:"required"`
	Role           string `json:"role"           validate:"required,min=1"`
}
