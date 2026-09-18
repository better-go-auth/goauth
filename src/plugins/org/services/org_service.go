// Package orgsvc implements IOrgService for multi-tenancy.
package orgsvc

import (
	"context"
	"fmt"
	"strings"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	corerepo "github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/app/services/serv_interfaces"
	autherr "github.com/better-go-auth/goauth/src/common/error"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	"github.com/better-go-auth/goauth/src/config"
	coremodels "github.com/better-go-auth/goauth/src/models"

	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	"github.com/better-go-auth/goauth/src/plugins/org/dtos"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
	orgrepo "github.com/better-go-auth/goauth/src/plugins/org/repository"
)

// OrgService implements IOrgService.
type OrgService struct {
	orgRepo     orgrepo.IOrgRepo
	memberRepo  orgrepo.IMemberRepo
	inviteRepo  orgrepo.IInvitationRepo
	sessionServ serv_interfaces.ISessionService
	// sessionRepo repoimpl2.ISessionRepo
	userRepo corerepo.IUserRepo
	// emailSender emailiface.IVerificationSender
	// baseURL     string
	// basePath    string
	txManager interfaces.ITransactionManager

	Cfg    config.AuthConfig
	Config orgconfig.OrgConfig
}

var _ IOrgService = (*OrgService)(nil)

// New creates a new OrgService.
func New(
	orgRepo orgrepo.IOrgRepo,
	memberRepo orgrepo.IMemberRepo,
	inviteRepo orgrepo.IInvitationRepo,
	txManager interfaces.ITransactionManager,
	authRepos repo_interfaces.IAuthRepos,
) *OrgService {
	// if basePath == "" {
	// 	basePath = "/api/auth"
	// }
	return &OrgService{
		orgRepo:    orgRepo,
		memberRepo: memberRepo,
		inviteRepo: inviteRepo,
		userRepo:   authRepos,
		// sessionRepo: sessionRepo,
		// userRepo:    userRepo,
		// emailSender: emailSender,
		// baseURL:     baseURL,
		// basePath:    basePath,
		txManager: txManager,
	}
}

// ─── Org CRUD ─────────────────────────────────────────────────────────────────

func (s *OrgService) CreateOrganization(ctx context.Context, creatorUserID string, input dtos.CreateOrgInput) (*models.Organization, error) {
	slug := strings.ToLower(strings.TrimSpace(input.Slug))

	// Check slug uniqueness
	if existing, err := s.orgRepo.GetOrgBySlug(ctx, slug); err == nil && existing != nil {
		return nil, autherr.ErrSlugTaken
	}

	now := new(coremodels.TimeNow())
	org := &models.Organization{
		Base:      coremodels.Base{ID: coremodels.NewID(), CreatedAt: now, UpdatedAt: now},
		Name:      input.Name,
		Slug:      slug,
		Logo:      input.Logo,
		Metadata:  input.Metadata,
		CreatedBy: creatorUserID,
	}
	var created *models.Organization
	err := s.txManager.Transaction(ctx, func(txCtx context.Context) error {
		var err error
		created, err = s.orgRepo.CreateOrg(txCtx, org)
		if err != nil {
			return fmt.Errorf("orgsvc: create org: %w", err)
		}

		// Add creator as owner
		member := &models.Member{
			Base:           coremodels.Base{ID: coremodels.NewID(), CreatedAt: now, UpdatedAt: now},
			OrganizationID: created.ID,
			UserID:         creatorUserID,
			Role:           models.OrgRoleOwner,
		}
		if _, err := s.memberRepo.CreateMember(txCtx, member); err != nil {
			return fmt.Errorf("orgsvc: add owner member: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

func (s *OrgService) GetOrganization(ctx context.Context, orgID string) (*models.Organization, error) {
	org, err := s.orgRepo.GetOrgByID(ctx, orgID)
	if err != nil {
		return nil, autherr.ErrOrgNotFound
	}
	return org, nil
}

func (s *OrgService) UpdateOrganization(ctx context.Context, orgID string, input dtos.UpdateOrgInput) (*models.Organization, error) {
	data := map[string]interface{}{}
	if input.Name != nil {
		data["name"] = *input.Name
	}
	if input.Slug != nil {
		slug := strings.ToLower(strings.TrimSpace(*input.Slug))
		if existing, err := s.orgRepo.GetOrgBySlug(ctx, slug); err == nil && existing != nil && existing.ID != orgID {
			return nil, autherr.ErrSlugTaken
		}
		data["slug"] = slug
	}
	if input.Logo != nil {
		data["logo"] = *input.Logo
	}
	if input.Metadata != nil {
		data["metadata"] = *input.Metadata
	}
	if len(data) == 0 {
		return s.orgRepo.GetOrgByID(ctx, orgID)
	}
	org, err := s.orgRepo.UpdateOrg(ctx, orgID, data)
	if err != nil {
		return nil, fmt.Errorf("orgsvc: update org: %w", err)
	}
	return org, nil
}

func (s *OrgService) DeleteOrganization(ctx context.Context, orgID, requestingUserID string) error {
	member, err := s.memberRepo.GetMemberByOrgAndUser(ctx, orgID, requestingUserID)
	if err != nil || member == nil || member.Role != models.OrgRoleOwner {
		return autherr.ErrForbidden
	}
	return s.orgRepo.DeleteOrg(ctx, orgID)
}

func (s *OrgService) ListOrganizations(ctx context.Context, userID string) ([]models.Organization, error) {
	return s.orgRepo.ListOrgsByUserID(ctx, userID)
}

// ─── Active Organization ──────────────────────────────────────────────────────

func (s *OrgService) SetActiveOrganization(ctx context.Context, sessionID string, orgID *string, userId, role string) (*coremodels.AuthTokens, error) {
	var member *models.Member
	var err error
	if orgID != nil {
		// users org role
		member, err = s.memberRepo.GetMemberByOrgAndUser(ctx, *orgID, userId)
		if err != nil {
			return nil, err
		}
		if member == nil {
			return nil, autherr.ErrForbidden
		}
	}
	// TODO make sure cached tokens and etc are updated and same sessin with old ord id is not used
	// use some sort of version mechanism and etc
	resp, err := s.sessionServ.CreateSession(ctx, sessionID, role, userId, &coremodels.SessionOpt{
		OrgRole:     new(member.Role.String()),
		ActiveOrgID: orgID,
	})
	return resp, err
}
