// Package orgsvc defines the org service interface and implementation.
package orgsvc

import (
	"context"

	authdtos "github.com/better-go-auth/goauth/src/models/dtos"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	"github.com/better-go-auth/goauth/src/plugins/org/dtos"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
)

// IOrgService defines the business-logic surface for the org plugin.
type IOrgService interface {
	ITeamService

	// Orgs
	CreateOrganization(ctx context.Context, creatorUserID string, input dtos.CreateOrgInput) (*models.Organization, error)
	GetOrganization(ctx context.Context, orgID string) (*models.Organization, error)
	GetOrganizationBySlug(ctx context.Context, slug string) (*models.Organization, error)
	CheckSlug(ctx context.Context, slug string) (bool, error)
	UpdateOrganization(ctx context.Context, orgID string, input dtos.UpdateOrgInput, requestingUserID string) (*models.Organization, error)
	DeleteOrganization(ctx context.Context, orgID string, requestingUserID string) error
	ListOrganizations(ctx context.Context, userID string) ([]models.Organization, error)

	// Active org
	SetActiveOrganization(ctx context.Context, sessionID string, orgID *string, userId, role string) (*authdtos.SessionWithUser, error)

	// Invitations
	InviteMember(ctx context.Context, inviterUserID string, input dtos.InviteMemberInput) (*models.Invitation, error)
	GetInvitation(ctx context.Context, invitationID string) (*models.Invitation, error)
	GetInvitationForUser(ctx context.Context, invitationID, requestingUserID string) (*models.Invitation, error)
	UserEmail(ctx context.Context, userID string) (string, error)
	AcceptInvitation(ctx context.Context, invitationID, userID string) error
	RejectInvitation(ctx context.Context, invitationID, userID string) error
	CancelInvitation(ctx context.Context, invitationID, requestingUserID string) error
	ListInvitations(ctx context.Context, orgID string, pagi models.Pagination) ([]models.Invitation, int64, error)

	// Members
	GetMember(ctx context.Context, orgID, userID string) (*models.Member, error)
	GetMemberByID(ctx context.Context, memberID string) (*models.Member, error)
	ResolveMemberID(ctx context.Context, orgID, memberIDOrEmail string) (string, error)
	ListMembers(ctx context.Context, orgID string, pagi models.Pagination) ([]models.Member, int64, error)
	UpdateMemberRole(ctx context.Context, input dtos.UpdateMemberRoleInput, requestingUserID string) (*models.Member, error)
	RemoveMember(ctx context.Context, input dtos.RemoveMemberInput, requestingUserID string) error

	// Admin-only org management
	AdminApproveOrg(ctx context.Context, orgID string) (*models.Organization, error)
	AdminBlockOrg(ctx context.Context, orgID, reason string) (*models.Organization, error)
	AdminUnblockOrg(ctx context.Context, orgID string) (*models.Organization, error)
	AdminListOrganizations(ctx context.Context, status *models.OrgStatus, pagi models.Pagination) ([]models.Organization, int64, error)
}

// ITeamService defines operations for team and dynamic access control management.
type ITeamService interface {
	TeamsEnabled() bool
	DynamicAccessControlEnabled() bool

	// Teams
	CreateTeam(ctx context.Context, input dtos.CreateTeamInput, requestingUserID string) (*models.Team, error)
	GetTeam(ctx context.Context, teamID string, requestingUserID string) (*models.Team, error)
	UpdateTeam(ctx context.Context, input dtos.UpdateTeamInput, requestingUserID string) (*models.Team, error)
	DeleteTeam(ctx context.Context, input dtos.DeleteTeamInput, requestingUserID string) error
	ListTeams(ctx context.Context, orgID string, requestingUserID string, pagi models.Pagination) ([]models.Team, int64, error)
	AddTeamMember(ctx context.Context, input dtos.AddTeamMemberInput, requestingUserID string) (*models.TeamMember, error)
	RemoveTeamMember(ctx context.Context, input dtos.RemoveTeamMemberInput, requestingUserID string) error
	ListTeamMembers(ctx context.Context, teamID string, requestingUserID string, pagi models.Pagination) ([]models.TeamMember, int64, error)
	SetActiveTeam(ctx context.Context, sessionID string, teamID *string, userID string) (*authdtos.SessionWithUser, error)

	// Dynamic Access Control
	CreateRole(ctx context.Context, orgID, role string, permission models.Permission, requestingUserID string) (*models.OrganizationRole, error)
	CreateRoleWithOps(ctx context.Context, orgID, role string, permission models.Permission, ops models.Operations, requestingUserID string) (*models.OrganizationRole, error)
	GetRole(ctx context.Context, orgID, role, requestingUserID string) (*models.OrganizationRole, error)
	UpdateRole(ctx context.Context, orgID, role string, permission models.Permission, requestingUserID string) (*models.OrganizationRole, error)
	UpdateRoleWithOps(ctx context.Context, orgID, role string, permission models.Permission, ops models.Operations, requestingUserID string) (*models.OrganizationRole, error)
	DeleteRole(ctx context.Context, orgID, role, requestingUserID string) error
	ListRoles(ctx context.Context, orgID, requestingUserID string) ([]models.OrganizationRole, error)
	HasPermission(ctx context.Context, orgID, role, resource, action string) (bool, error)
	HasOperation(ctx context.Context, orgID, role, operationID string) (bool, error)
	AuthorizeRole(ctx context.Context, orgID, role string, check AuthCheck) (bool, error)
}

// AuthCheck specifies parameters for dynamic role authorization.
type AuthCheck struct {
	Resource    string
	Action      string
	OperationID string
	Method      orgconfig.AuthMethod
}

func (s *OrgService) TeamsEnabled() bool {
	return s.Config.Teams != nil && s.Config.Teams.Enabled
}

func (s *OrgService) DynamicAccessControlEnabled() bool {
	return s.Config.DynamicAccessControl != nil && s.Config.DynamicAccessControl.Enabled
}
