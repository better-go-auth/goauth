// Package orgsvc defines the org service interface and implementation.
package orgsvc

import (
	"context"

	coremodels "github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins/org/dtos"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
)

// IOrgService defines the business-logic surface for the org plugin.
type IOrgService interface {
	// Orgs
	CreateOrganization(ctx context.Context, creatorUserID string, input dtos.CreateOrgInput) (*models.Organization, error)
	GetOrganization(ctx context.Context, orgID string) (*models.Organization, error)
	UpdateOrganization(ctx context.Context, orgID string, input dtos.UpdateOrgInput) (*models.Organization, error)
	DeleteOrganization(ctx context.Context, orgID, requestingUserID string) error
	ListOrganizations(ctx context.Context, userID string) ([]models.Organization, error)

	// Active org
	SetActiveOrganization(ctx context.Context, sessionID string, orgID *string, userId , role string) (*coremodels.AuthTokens,error)

	// Invitations
	InviteMember(ctx context.Context, inviterUserID string, input dtos.InviteMemberInput) (*models.Invitation, error)
	GetInvitation(ctx context.Context, invitationID string) (*models.Invitation, error)
	AcceptInvitation(ctx context.Context, invitationID, userID string) error
	RejectInvitation(ctx context.Context, invitationID, userID string) error
	CancelInvitation(ctx context.Context, invitationID, requestingUserID string) error
	ListInvitations(ctx context.Context, orgID string, pagi models.Pagination) ([]models.Invitation, int64, error)

	// Members
	GetMember(ctx context.Context, orgID, userID string) (*models.Member, error)
	ListMembers(ctx context.Context, orgID string, pagi models.Pagination) ([]models.Member, int64, error)
	UpdateMemberRole(ctx context.Context, input dtos.UpdateMemberRoleInput, requestingUserID string) (*models.Member, error)
	RemoveMember(ctx context.Context, input dtos.RemoveMemberInput, requestingUserID string) error
}
