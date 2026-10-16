// Package orgrepo defines the repository interfaces for the org plugin.
package orgrepo

import (
	"context"

	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
)

// IOrgRepo defines the repository interface for Organization persistence.
type IOrgRepo interface {
	CreateOrg(ctx context.Context, org *models.Organization) (*models.Organization, error)
	GetOrgByID(ctx context.Context, id string) (*models.Organization, error)
	GetOrgBySlug(ctx context.Context, slug string) (*models.Organization, error)
	UpdateOrg(ctx context.Context, id string, data map[string]interface{}) (*models.Organization, error)
	DeleteOrg(ctx context.Context, id string) error
	// ListOrgsByUserID returns all organizations where the user is a member.
	ListOrgsByUserID(ctx context.Context, userID string) ([]models.Organization, error)
	// ListAllOrgs returns all organizations with optional status filter (admin use).
	ListAllOrgs(ctx context.Context, status *models.OrgStatus, pagi models.Pagination) ([]models.Organization, int64, error)
}

// IMemberRepo defines the repository interface for Member persistence.
type IMemberRepo interface {
	CreateMember(ctx context.Context, member *models.Member) (*models.Member, error)
	GetMemberByOrgAndUser(ctx context.Context, orgID, userID string) (*models.Member, error)
	GetMemberByID(ctx context.Context, id string) (*models.Member, error)
	UpdateMember(ctx context.Context, id string, data map[string]interface{}) (*models.Member, error)
	DeleteMemberByID(ctx context.Context, id string) error
	DeleteMemberByOrgAndUser(ctx context.Context, orgID, userID string) error
	ListMembersByOrgID(ctx context.Context, orgID string, pagi models.Pagination) ([]models.Member, int64, error)
}

// IInvitationRepo defines the repository interface for Invitation persistence.
type IInvitationRepo interface {
	CreateInvitation(ctx context.Context, inv *models.Invitation) (*models.Invitation, error)
	GetInvitationByID(ctx context.Context, id string) (*models.Invitation, error)
	GetInvitationByOrgAndEmail(ctx context.Context, orgID, email string) (*models.Invitation, error)
	UpdateInvitation(ctx context.Context, id string, data map[string]interface{}) (*models.Invitation, error)
	DeleteInvitationByID(ctx context.Context, id string) error
	ListInvitationsByOrgID(ctx context.Context, orgID string, pagi models.Pagination) ([]models.Invitation, int64, error)
	ListInvitationsByEmail(ctx context.Context, email string) ([]models.Invitation, error)
}

// ITeamRepo defines the repository interface for Team persistence (requires Teams.Enabled).
type ITeamRepo interface {
	CreateTeam(ctx context.Context, team *models.Team) (*models.Team, error)
	GetTeamByID(ctx context.Context, id string) (*models.Team, error)
	ListTeamsByOrgID(ctx context.Context, orgID string, pagi models.Pagination) ([]models.Team, int64, error)
	UpdateTeam(ctx context.Context, id string, data map[string]interface{}) (*models.Team, error)
	DeleteTeam(ctx context.Context, id string) error
}

// ITeamMemberRepo defines the repository interface for TeamMember persistence.
type ITeamMemberRepo interface {
	CreateTeamMember(ctx context.Context, m *models.TeamMember) (*models.TeamMember, error)
	GetTeamMember(ctx context.Context, teamID, userID string) (*models.TeamMember, error)
	ListMembersByTeamID(ctx context.Context, teamID string, pagi models.Pagination) ([]models.TeamMember, int64, error)
	DeleteTeamMember(ctx context.Context, teamID, userID string) error
}

// IOrganizationRoleRepo defines the repository interface for OrganizationRole persistence
// (requires DynamicAccessControl.Enabled).
type IOrganizationRoleRepo interface {
	CreateRole(ctx context.Context, r *models.OrganizationRole) (*models.OrganizationRole, error)
	GetRole(ctx context.Context, orgID, role string) (*models.OrganizationRole, error)
	ListRolesByOrgID(ctx context.Context, orgID string) ([]models.OrganizationRole, error)
	UpdateRole(ctx context.Context, orgID, role string, permission string) (*models.OrganizationRole, error)
	DeleteRole(ctx context.Context, orgID, role string) error
}

// OrgRepositories configures the Org plugin.
type OrgRepositories struct {
	// OrgRepo overrides default org repository.
	 IOrgRepo
	// MemberRepo overrides default member repository.
	 IMemberRepo
	// InviteRepo overrides default invitation repository.
	 IInvitationRepo
	 // TeamRepo / TeamMemberRepo / OrganizationRoleRepo are opt-in (see OrgConfig).
	 ITeamRepo
	 ITeamMemberRepo
	 IOrganizationRoleRepo
	// Migrator overrides default org migrator.
	 migration.IMigrator
}
type IOrgRepos interface {
	IOrgRepo
	IMemberRepo
	IInvitationRepo
	ITeamRepo
	ITeamMemberRepo
	IOrganizationRoleRepo
	migration.IMigrator
}
