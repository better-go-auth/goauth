package config

import (
	"context"
	"time"
)

type TeamsConfig struct {
	Enabled               bool
	DefaultTeam           *bool // nil means create default team on org creation (better-auth default: true)
	MaximumTeams          *int  // nil = unlimited
	MaximumMembersPerTeam *int  // nil = unlimited
	AllowRemovingAllTeams bool
}

type DynamicAccessControlConfig struct {
	Enabled bool
}

type OrgConfig struct {
	InvitaionConfig
	// Weither the org will be pending and needs to be approved by the admins after creation
	OrgNeedsApproval bool

	// Teams mirrors better-auth `organization.teams` (opt-in). When nil/disabled, team tables
	// still migrate but team endpoints return 404 and invitation.teamId is ignored.
	Teams *TeamsConfig
	// DynamicAccessControl mirrors better-auth `organization.dynamicAccessControl` (opt-in).
	// When enabled, permissions are read from the `organizationRole` table instead of static roles.
	DynamicAccessControl *DynamicAccessControlConfig

	// better-auth compat fields (stored but not yet enforced - see backlog):
	AllowUserToCreateOrganization *bool // nil = true (better-auth default)
	OrganizationLimit             *int  // nil = unlimited
	CreatorRole                   string // default "owner"
	MembershipLimit               int    // default 100
	InvitationLimit               int    // default 100
}

type InvitaionConfig struct {
	SendOrgInvitation       SendOrgInvitation
	InvitationNeedsApproval bool
	InvitationExpiresIn     time.Duration
}

// SendOrgInvitation sends an organization invite email.
type SendOrgInvitation func(ctx context.Context, to, inviterName, orgName, inviteURL string) error
