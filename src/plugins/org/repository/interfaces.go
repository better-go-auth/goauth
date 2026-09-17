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

// OrgRepositories configures the Org plugin.
type OrgRepositories struct {
	// OrgRepo overrides default org repository.
	 IOrgRepo
	// MemberRepo overrides default member repository.
	 IMemberRepo
	// InviteRepo overrides default invitation repository.
	 IInvitationRepo
	// Migrator overrides default org migrator.
	 migration.IMigrator
}
type IOrgRepos interface {
	IOrgRepo
	IMemberRepo
	IInvitationRepo
	migration.IMigrator
}
