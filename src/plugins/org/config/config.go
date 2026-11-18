package config

import (
	"context"
	"time"

	coremodels "github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
	"github.com/better-go-auth/goauth/src/providers/access"
)

// DefaultTeamConfig defines default team settings on organization creation.
type DefaultTeamConfig struct {
	// Enabled determines whether to create a default team when an organization is created (default: true).
	Enabled *bool
	// CustomCreateDefaultTeam allows custom creation of the default team.
	CustomCreateDefaultTeam func(ctx context.Context, org *models.Organization) (*models.Team, error)
}

// TeamLimitData passes context to dynamic team limits.
type TeamLimitData struct {
	OrganizationID string
	User           *coremodels.User
}

// TeamMemberLimitData passes context to dynamic team member limits.
type TeamMemberLimitData struct {
	TeamID         string
	OrganizationID string
	User           *coremodels.User
}

// TeamsConfig mirrors better-auth `organization.teams` options.
type TeamsConfig struct {
	Enabled                 bool
	DefaultTeam             *DefaultTeamConfig
	MaximumTeams            *int
	MaximumTeamsFn          func(ctx context.Context, data TeamLimitData) (int, error)
	MaximumMembersPerTeam   *int
	MaximumMembersPerTeamFn func(ctx context.Context, data TeamMemberLimitData) (int, error)
	AllowRemovingAllTeams   bool
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

// DynamicAccessControlConfig mirrors better-auth `organization.dynamicAccessControl` options.
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
	// MaximumRolesPerOrganization limits the maximum number of roles created per organization.
	MaximumRolesPerOrganization *int
	// MaximumRolesPerOrganizationFn dynamically computes the maximum roles allowed.
	MaximumRolesPerOrganizationFn func(ctx context.Context, orgID string) (int, error)
}

// InvitationLimitData passes context to dynamic invitation limits.
type InvitationLimitData struct {
	User         *coremodels.User
	Organization *models.Organization
	Member       *models.Member
}

// OrgSchemaConfig mirrors better-auth `schema` option for model and field customization.
type OrgSchemaConfig struct {
	Session *struct {
		Fields map[string]string
	}
	Organization *struct {
		ModelName string
		Fields    map[string]string
	}
	Member *struct {
		ModelName string
		Fields    map[string]string
	}
	Invitation *struct {
		ModelName string
		Fields    map[string]string
	}
	Team *struct {
		ModelName string
		Fields    map[string]string
	}
	TeamMember *struct {
		ModelName string
		Fields    map[string]string
	}
	OrganizationRole *struct {
		ModelName string
		Fields    map[string]string
	}
}

// OrgConfig mirrors better-auth `OrganizationOptions` configuration.
type OrgConfig struct {
	InvitaionConfig
	// Whether the org will be pending and needs to be approved by the admins after creation
	OrgNeedsApproval bool

	// Teams mirrors better-auth `organization.teams` (opt-in). When nil/disabled, team tables
	// still migrate but team endpoints return 404 and invitation.teamId is ignored.
	Teams *TeamsConfig
	// DynamicAccessControl mirrors better-auth `organization.dynamicAccessControl` (opt-in).
	// When enabled, permissions are read from the `organizationRole` table instead of static roles.
	DynamicAccessControl *DynamicAccessControlConfig

	// AllowUserToCreateOrganization configures whether users are allowed to create organizations.
	// nil means true (better-auth default).
	AllowUserToCreateOrganization *bool
	// AllowUserToCreateOrganizationFn dynamic function determining if a user can create an organization.
	AllowUserToCreateOrganizationFn func(ctx context.Context, user *coremodels.User) (bool, error)

	// OrganizationLimit specifies the maximum number of organizations a user can create.
	// nil means unlimited.
	OrganizationLimit *int
	// OrganizationLimitFn dynamic function returning true if limit is reached, false otherwise.
	OrganizationLimitFn func(ctx context.Context, user *coremodels.User) (bool, error)

	// CreatorRole assigned to the creator of the organization (default: "owner").
	CreatorRole string

	// MembershipLimit specifies maximum members allowed in an organization (default: 100).
	MembershipLimit *int
	// MembershipLimitFn dynamic function returning the membership limit for the organization.
	MembershipLimitFn func(ctx context.Context, user *coremodels.User, org *models.Organization) (int, error)

	// Roles defines custom static permissions for roles.
	// Legacy goauth option (supports "*" wildcards); ignored in better-auth mode (see AccessRoles).
	Roles map[string]models.Permission

	// AccessControl mirrors better-auth's organization `ac` option (createAccessControl). Setting it
	// switches permission checks to exact better-auth semantics (see BetterAuthMode) and enables the
	// INVALID_RESOURCE check on dynamic roles. Default (better-auth mode): DefaultAC.
	AccessControl *access.AccessControl

	// AccessRoles mirrors better-auth's organization `roles` option (role name -> access.Role).
	// Setting it switches to better-auth semantics; these roles replace the default owner/admin/member.
	AccessRoles map[string]access.Role

	// BetterAuthPermissions forces better-auth semantics even when the legacy Roles map is set.
	//
	// Deprecated: better-auth semantics are the default now; set GoAuth.LegacyPermissions for the old rules.
	BetterAuthPermissions bool

	// GoAuth holds organization options better-auth doesn't have.
	GoAuth OrgGoAuth

	// CancelPendingInvitationsOnReInvite cancels existing pending invitations when re-inviting (default: false).
	CancelPendingInvitationsOnReInvite *bool

	// RequireEmailVerificationOnInvitation requires verified email before accepting/rejecting invitations (default: false).
	RequireEmailVerificationOnInvitation bool

	// DisableOrganizationDeletion prevents deleting organizations (default: false).
	DisableOrganizationDeletion bool

	// InvitationLimit specifies maximum invitations an organization can have (default: 100).
	InvitationLimit *int
	// InvitationLimitFn dynamic function determining invitation limit.
	InvitationLimitFn func(ctx context.Context, data InvitationLimitData) (int, error)

	// OrganizationHooks contains lifecycle callbacks matching better-auth organizationHooks.
	OrganizationHooks OrganizationHooks

	// Schema contains model/field mapping configuration.
	Schema *OrgSchemaConfig
}

type InvitaionConfig struct {
	SendOrgInvitation       SendOrgInvitation
	SendInvitationEmail     SendInvitationEmail
	InvitationNeedsApproval bool
	InvitationExpiresIn     time.Duration
}

// SendOrgInvitation sends an organization invite email (legacy signature).
type SendOrgInvitation func(ctx context.Context, to, inviterName, orgName, inviteURL string) error

// SendInvitationInput passes data to SendInvitationEmail callback matching better-auth.
type SendInvitationInput struct {
	ID           string
	Role         string
	Email        string
	Organization models.Organization
	Invitation   models.Invitation
	Inviter      models.Member
	InviterUser  *coremodels.User
}

// SendInvitationData is an alias for SendInvitationInput.
type SendInvitationData = SendInvitationInput

// SendInvitationEmail sends an email with the invitation link matching better-auth.
type SendInvitationEmail func(ctx context.Context, input SendInvitationInput) error

// OrgGoAuth holds organization options better-auth doesn't have.
type OrgGoAuth struct {
	// LegacyPermissions switches organization permission checks to goauth's legacy rules instead of
	// better-auth's access control (the default): owner bypasses every check, admin may do everything
	// except organization:delete/update-role, member may only read/list/get, and Config.Roles (with "*"
	// wildcards) defines extra roles. Setting Config.Roles also selects the legacy rules. Dynamic (DB)
	// roles are merged into the predefined roles and comma-separated multi-role members work in both modes.
	// Ignored when AccessControl or AccessRoles is set.
	LegacyPermissions bool
}
