// Package orgsvc implements IOrgService for multi-tenancy.
package orgsvc

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	corerepo "github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	serv_interfaces "github.com/better-go-auth/goauth/src/app/services/interfaces"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
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
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
)

// l1RoleCacheItem holds in-memory cached organization roles with expiration.
type l1RoleCacheItem struct {
	roles     map[string]*models.OrganizationRole
	expiresAt time.Time
}

// OrgService implements IOrgService.
type OrgService struct {
	orgRepo        orgrepo.IOrgRepo
	memberRepo     orgrepo.IMemberRepo
	inviteRepo     orgrepo.IInvitationRepo
	teamRepo       orgrepo.ITeamRepo
	teamMemberRepo orgrepo.ITeamMemberRepo
	orgRoleRepo    orgrepo.IOrganizationRoleRepo
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

	// SecondaryStorage and L1 in-memory cache for dynamic role definitions (Phase 6)
	secStorage sec_storage.SecondaryStorage
	l1Roles    sync.Map // key: orgID (string), val: *l1RoleCacheItem
}

var _ IOrgService = (*OrgService)(nil)

// SetHooks configures lifecycle hooks on the org service.
func (s *OrgService) SetHooks(hooks plugins.HookRegistry) {
	s.hooks = hooks
}

// SetSessionService configures the normal session service on the org service.
func (s *OrgService) SetSessionService(sessionServ serv_interfaces.ISessionManager) {
	s.sessionMgr = sessionServ
}

// SetRepositories configures team and role repos on the org service
// conditionally based on whether teams or dynamic access control are enabled.
func (s *OrgService) SetRepositories(repos orgrepo.OrgRepositories) {
	// Step 1: If teams are enabled in config, set the team and team member repositories
	if s.TeamsEnabled() {
		s.teamRepo = repos.ITeamRepo
		s.teamMemberRepo = repos.ITeamMemberRepo
	}
	// Step 2: If dynamic access control is enabled in config, set the organization role repository
	if s.DynamicAccessControlEnabled() {
		s.orgRoleRepo = repos.IOrganizationRoleRepo
	}
}

// SetSecondaryStorage configures secondary storage for dynamic role caching.
func (s *OrgService) SetSecondaryStorage(storage sec_storage.SecondaryStorage) {
	s.secStorage = storage
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

		// If teams are enabled and default team is configured, create default team
		if s.TeamsEnabled() && s.teamRepo != nil {
			if s.Config.Teams.DefaultTeam == nil || *s.Config.Teams.DefaultTeam {
				defaultTeam := &models.Team{
					Base:           coremodels.Base{ID: coremodels.NewID(), CreatedAt: now, UpdatedAt: now},
					Name:           created.Name,
					OrganizationID: created.ID,
				}
				if createdTeam, err := s.teamRepo.CreateTeam(txCtx, defaultTeam); err == nil && s.teamMemberRepo != nil {
					tm := &models.TeamMember{
						Base:   coremodels.Base{ID: coremodels.NewID(), CreatedAt: now, UpdatedAt: now},
						TeamID: createdTeam.ID,
						UserID: creatorUserID,
					}
					_, _ = s.teamMemberRepo.CreateTeamMember(txCtx, tm)
				}
			}
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
	requester, err := s.memberRepo.GetMemberByOrgAndUser(ctx, orgID, requestingUserID)
	if err != nil || !isAdminOrOwner(requester) {
		return nil, autherr.ErrForbidden
	}
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
	if err := s.orgRepo.DeleteOrg(ctx, orgID); err != nil {
		return err
	}
	s.invalidateRoleCache(ctx, orgID)
	return nil
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
		r := member.Role.Str()
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

// ─── Dynamic Role Caching Helpers (Phase 6 Architecture) ─────────────────────

func (s *OrgService) getL1Roles(orgID string) (map[string]*models.OrganizationRole, bool) {
	val, ok := s.l1Roles.Load(orgID)
	if !ok {
		return nil, false
	}
	item, ok := val.(*l1RoleCacheItem)
	if !ok || item == nil {
		return nil, false
	}
	if time.Now().After(item.expiresAt) {
		s.l1Roles.Delete(orgID)
		return nil, false
	}
	return item.roles, true
}

func (s *OrgService) setL1Roles(orgID string, roles map[string]*models.OrganizationRole) {
	ttl := s.l1CacheTTL()
	s.l1Roles.Store(orgID, &l1RoleCacheItem{
		roles:     roles,
		expiresAt: time.Now().Add(ttl),
	})
}

func (s *OrgService) deleteL1Roles(orgID string) {
	s.l1Roles.Delete(orgID)
}

func (s *OrgService) roleCacheTTL() time.Duration {
	if s.Config.DynamicAccessControl != nil && s.Config.DynamicAccessControl.CacheTTL > 0 {
		return s.Config.DynamicAccessControl.CacheTTL
	}
	return 30 * time.Minute
}

func (s *OrgService) l1CacheTTL() time.Duration {
	if s.Config.DynamicAccessControl != nil && s.Config.DynamicAccessControl.L1CacheTTL > 0 {
		return s.Config.DynamicAccessControl.L1CacheTTL
	}
	return 1 * time.Minute
}

func (s *OrgService) isRoleCacheEnabled() bool {
	if s.Config.DynamicAccessControl == nil {
		return false
	}
	if s.Config.DynamicAccessControl.CacheRoles != nil {
		return *s.Config.DynamicAccessControl.CacheRoles
	}
	return true
}

func (s *OrgService) invalidateRoleCache(ctx context.Context, orgID string) {
	s.deleteL1Roles(orgID)
	if s.secStorage != nil && orgID != "" {
		cacheKey := fmt.Sprintf("goauth:org:%s:roles", orgID)
		_ = s.secStorage.Delete(ctx, cacheKey)
	}
}

func (s *OrgService) getOrgRolesCached(ctx context.Context, orgID string) (map[string]*models.OrganizationRole, error) {
	// Step 1: Check L1 local in-memory cache (<50ns sub-microsecond latency)
	if cached, ok := s.getL1Roles(orgID); ok && cached != nil {
		return cached, nil
	}

	// Step 2: Check L2 secondary storage (Redis / Memory storage)
	if s.secStorage != nil && s.isRoleCacheEnabled() && orgID != "" {
		cacheKey := fmt.Sprintf("goauth:org:%s:roles", orgID)
		val, exists, err := s.secStorage.Get(ctx, cacheKey)
		if err == nil && exists && val != nil {
			if roles, err := unmarshalCachedRoles(val); err == nil && len(roles) > 0 {
				s.setL1Roles(orgID, roles)
				return roles, nil
			}
		}
	}

	// Step 3: L3 fallback to Database
	if s.orgRoleRepo == nil {
		return make(map[string]*models.OrganizationRole), nil
	}
	dbRoles, err := s.orgRoleRepo.ListRolesByOrgID(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("orgsvc: list roles from db: %w", err)
	}

	rolesMap := make(map[string]*models.OrganizationRole, len(dbRoles))
	for i := range dbRoles {
		r := dbRoles[i]
		rolesMap[r.Role] = &r
	}

	// Step 4: Populate L1 and L2 caches
	s.setL1Roles(orgID, rolesMap)
	if s.secStorage != nil && s.isRoleCacheEnabled() && orgID != "" {
		cacheKey := fmt.Sprintf("goauth:org:%s:roles", orgID)
		if jsonBytes, err := json.Marshal(rolesMap); err == nil {
			_ = s.secStorage.Set(ctx, cacheKey, string(jsonBytes), s.roleCacheTTL())
		}
	}

	return rolesMap, nil
}

func unmarshalCachedRoles(val any) (map[string]*models.OrganizationRole, error) {
	switch v := val.(type) {
	case map[string]*models.OrganizationRole:
		return v, nil
	case string:
		var m map[string]*models.OrganizationRole
		if err := json.Unmarshal([]byte(v), &m); err != nil {
			return nil, err
		}
		return m, nil
	case []byte:
		var m map[string]*models.OrganizationRole
		if err := json.Unmarshal(v, &m); err != nil {
			return nil, err
		}
		return m, nil
	default:
		b, err := json.Marshal(val)
		if err != nil {
			return nil, err
		}
		var m map[string]*models.OrganizationRole
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
		return m, nil
	}
}
