// Package orgsvc implements IOrgService for multi-tenancy.
package orgsvc

import (
	"context"
	"fmt"
	"strings"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	corerepo "github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/app/services/serv_interfaces"
	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	"github.com/better-go-auth/goauth/src/config"
	coremodels "github.com/better-go-auth/goauth/src/models"
	authdtos "github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins"

	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	"github.com/better-go-auth/goauth/src/plugins/org/dtos"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
	orgerrors "github.com/better-go-auth/goauth/src/plugins/org/org-errors"
	orgrepo "github.com/better-go-auth/goauth/src/plugins/org/repository"
)

// OrgService implements IOrgService.
type OrgService struct {
	orgRepo    orgrepo.IOrgRepo
	memberRepo orgrepo.IMemberRepo
	inviteRepo orgrepo.IInvitationRepo
	// sessionRepo repoimpl2.ISessionRepo
	// emailSender emailiface.IVerificationSender
	userRepo   corerepo.IUserRepo
	sessionMgr serv_interfaces.ISessionManager

	// baseURL     string
	// basePath    string
	txManager interfaces.ITransactionManager
	hooks     plugins.HookRegistry

	Cfg    config.AuthConfig
	Config orgconfig.OrgConfig
}

var _ IOrgService = (*OrgService)(nil)

// SetHooks configures lifecycle hooks on the org service.
func (s *OrgService) SetHooks(hooks plugins.HookRegistry) {
	s.hooks = hooks
}

// SetSessionService configures the normal session service on the org service.
func (s *OrgService) SetSessionService(sessionServ serv_interfaces.ISessionService) {
	s.sessionMgr = sessionServ
}

// HandleUserDeleted cleans up a deleted user's memberships across organizations.
func (s *OrgService) HandleUserDeleted(ctx context.Context, userID string) error {
	orgs, err := s.orgRepo.ListOrgsByUserID(ctx, userID)
	if err == nil {
		for _, o := range orgs {
			_ = s.memberRepo.DeleteMemberByOrgAndUser(ctx, o.ID, userID)
		}
	}
	return nil
}

// New creates a new OrgService.
func New(
	orgRepo orgrepo.IOrgRepo,
	memberRepo orgrepo.IMemberRepo,
	inviteRepo orgrepo.IInvitationRepo,
	txManager interfaces.ITransactionManager,
	authRepos repo_interfaces.IAuthRepos,
	sessionMgr serv_interfaces.ISessionManager,
) *OrgService {
	return &OrgService{
		orgRepo:    orgRepo,
		memberRepo: memberRepo,
		inviteRepo: inviteRepo,
		userRepo:   authRepos,
		sessionMgr: sessionMgr,
		txManager:  txManager,
	}
}

// ─── Org CRUD ─────────────────────────────────────────────────────────────────

func (s *OrgService) CreateOrganization(ctx context.Context, creatorUserID string, input dtos.CreateOrgInput) (*models.Organization, error) {
	slug := strings.ToLower(strings.TrimSpace(input.Slug))

	// Check slug uniqueness
	if existing, err := s.orgRepo.GetOrgBySlug(ctx, slug); err == nil && existing != nil {
		return nil, orgerrors.ErrSlugTaken
	}
	orgStatus := models.OrgStatusActive
	if s.Config.OrgNeedsApproval {
		orgStatus = models.OrgStatusPending
	}

	now := coremodels.TimeNow()
	org := &models.Organization{
		Base:      coremodels.Base{ID: coremodels.NewID(), CreatedAt: now, UpdatedAt: now},
		Name:      input.Name,
		Slug:      slug,
		Logo:      input.Logo,
		Metadata:  input.Metadata,
		CreatedBy: creatorUserID,
		Status:    orgStatus,
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
		return nil, orgerrors.ErrOrgNotFound
	}
	return org, nil
}

func (s *OrgService) UpdateOrganization(ctx context.Context, orgID string, input dtos.UpdateOrgInput, requestingUserID string) (*models.Organization, error) {
	data := map[string]interface{}{}
	if input.Name != nil {
		data["Name"] = *input.Name
	}
	if input.Slug != nil {
		slug := strings.ToLower(strings.TrimSpace(*input.Slug))
		if existing, err := s.orgRepo.GetOrgBySlug(ctx, slug); err == nil && existing != nil && existing.ID != orgID {
			return nil, orgerrors.ErrSlugTaken
		}
		data["Slug"] = slug
	}
	if input.Logo != nil {
		data["Logo"] = *input.Logo
	}
	if input.Metadata != nil {
		data["Metadata"] = *input.Metadata
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

func (s *OrgService) SetActiveOrganization(ctx context.Context, sessionID string, orgID *string, userId, role string) (*authdtos.SessionWithUser, error) {
	var member *models.Member
	var orgRole *string
	if orgID != nil && *orgID != "" {
		// Verify org exists and is active before allowing it to be set
		org, err := s.orgRepo.GetOrgByID(ctx, *orgID)
		if err != nil || org == nil {
			return nil, orgerrors.ErrOrgNotFound
		}
		switch org.Status {
		case models.OrgStatusPending:
			return nil, orgerrors.ErrOrgPending
		case models.OrgStatusSuspended:
			return nil, orgerrors.ErrOrgSuspended
		case models.OrgStatusInactive:
			return nil, orgerrors.ErrOrgNotActive
		}

		// user's org role
		member, err = s.memberRepo.GetMemberByOrgAndUser(ctx, *orgID, userId)
		if err != nil {
			return nil, err
		}
		if member == nil {
			return nil, orgerrors.ErrMemberNotFound
		}
		r := member.Role.String()
		orgRole = &r
	}

	data := map[string]any{
		"ActiveOrganizationID":   orgID,
		"ActiveOrganizationRole": orgRole,
	}

	var updatedSession *authdtos.SessionWithUser

	// 1. Better-Auth flow: update session via normal session service
	if s.sessionMgr != nil {
		if sRepo, ok := s.userRepo.(repo_interfaces.ISessionRepo); ok && sessionID != "" {
			dbSess, err := sRepo.FindSessionByID(ctx, sessionID)
			if err == nil && dbSess != nil {
				sw, err := s.sessionMgr.Get(ctx, dbSess.Token)
				if err == nil && sw != nil {
					updatedSession, _ = s.sessionMgr.Update(ctx, sw, data)
				}
			}
		}
		if updatedSession == nil && sessionID != "" {
			sw, err := s.sessionMgr.Get(ctx, sessionID)
			if err == nil && sw != nil {
				updatedSession, _ = s.sessionMgr.Update(ctx, sw, data)
			}
		}
	}

	// 2. Direct DB fallback
	if updatedSession == nil {
		if sRepo, ok := s.userRepo.(repo_interfaces.ISessionRepo); ok && sessionID != "" {
			sess, err := sRepo.UpdateSession(ctx, sessionID, data)
			if err == nil && sess != nil {
				user, _ := s.userRepo.FindUserByID(ctx, userId)
				updatedSession = &authdtos.SessionWithUser{
					Session: authdtos.SessionFromModel(sess),
					User:    authdtos.UserFromModel(user),
				}
			}
		}
	}

	if s.hooks != nil && orgID != nil && *orgID != "" {
		_ = s.hooks.TriggerActiveOrgChanged(ctx, userId, *orgID)
	}

	if updatedSession == nil {
		return nil, fmt.Errorf("orgsvc: failed to update active organization on session")
	}

	return updatedSession, nil
}

// ─── Admin Org Management ─────────────────────────────────────────────────────

// AdminApproveOrg approves a pending organization, setting its status to active.
func (s *OrgService) AdminApproveOrg(ctx context.Context, orgID string) (*models.Organization, error) {
	org, err := s.orgRepo.GetOrgByID(ctx, orgID)
	if err != nil || org == nil {
		return nil, orgerrors.ErrOrgNotFound
	}
	if org.Status != models.OrgStatusPending {
		return nil, autherr.New("ORG_NOT_PENDING", "Organization is not pending approval", 400)
	}
	return s.orgRepo.UpdateOrg(ctx, orgID, map[string]interface{}{"Status": string(models.OrgStatusActive)})
}

// AdminBlockOrg suspends an organization.
func (s *OrgService) AdminBlockOrg(ctx context.Context, orgID, reason string) (*models.Organization, error) {
	org, err := s.orgRepo.GetOrgByID(ctx, orgID)
	if err != nil || org == nil {
		return nil, orgerrors.ErrOrgNotFound
	}
	updates := map[string]interface{}{"Status": string(models.OrgStatusSuspended)}
	if reason != "" {
		updates["Metadata"] = reason
	}
	return s.orgRepo.UpdateOrg(ctx, orgID, updates)
}

// AdminUnblockOrg re-activates a suspended or inactive organization.
func (s *OrgService) AdminUnblockOrg(ctx context.Context, orgID string) (*models.Organization, error) {
	org, err := s.orgRepo.GetOrgByID(ctx, orgID)
	if err != nil || org == nil {
		return nil, orgerrors.ErrOrgNotFound
	}
	return s.orgRepo.UpdateOrg(ctx, orgID, map[string]interface{}{"Status": string(models.OrgStatusActive)})
}

// AdminListOrganizations returns all organizations, optionally filtered by status.
func (s *OrgService) AdminListOrganizations(ctx context.Context, status *models.OrgStatus, pagi models.Pagination) ([]models.Organization, int64, error) {
	return s.orgRepo.ListAllOrgs(ctx, status, pagi)
}
