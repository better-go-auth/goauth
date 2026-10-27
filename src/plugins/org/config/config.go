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

// AuthMethod defines the authorization strategy used for dynamic role evaluation.
type AuthMethod string

const (
	// AuthMethodPermission evaluates resource and action permissions (e.g. "project:read").
	AuthMethodPermission AuthMethod = "permission"
	// AuthMethodOperations evaluates operation IDs in the Ops array (e.g. "createProject").
	AuthMethodOperations AuthMethod = "ops"
	// AuthMethodBoth evaluates both (grants access if either matches).
	AuthMethodBoth AuthMethod = "both"
)

type DynamicAccessControlConfig struct {
	Enabled bool
	// AuthMethod specifies whether to evaluate by Permission map, Ops array, or both (default: "permission").
	AuthMethod AuthMethod
	// CacheRoles enables L1 (in-memory) and L2 (secondary storage) dynamic role caching (Phase 6).
	// When nil or true, role definitions are cached on secondary storage and in process memory.
	CacheRoles *bool
	// CacheTTL defines the L2 secondary storage expiration (default: 30 minutes).
	CacheTTL time.Duration
	// L1CacheTTL defines the local in-memory cache expiration (default: 1 minute).
	L1CacheTTL time.Duration
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
