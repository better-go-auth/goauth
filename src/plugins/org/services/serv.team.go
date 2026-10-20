// Package orgsvc implements team and dynamic access control services.
package orgsvc

import (
	"context"
	"encoding/json"
	"fmt"

	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/config"
	coremodels "github.com/better-go-auth/goauth/src/models"
	authdtos "github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/plugins/org/dtos"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
	orgerrors "github.com/better-go-auth/goauth/src/plugins/org/org-errors"
)

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
	CreateRole(ctx context.Context, orgID, role, permission, requestingUserID string) (*models.OrganizationRole, error)
	GetRole(ctx context.Context, orgID, role, requestingUserID string) (*models.OrganizationRole, error)
	UpdateRole(ctx context.Context, orgID, role, permission, requestingUserID string) (*models.OrganizationRole, error)
	DeleteRole(ctx context.Context, orgID, role, requestingUserID string) error
	ListRoles(ctx context.Context, orgID, requestingUserID string) ([]models.OrganizationRole, error)
	HasPermission(ctx context.Context, orgID, role, resource, action string) (bool, error)
}

func (s *OrgService) TeamsEnabled() bool {
	return s.Config.Teams != nil && s.Config.Teams.Enabled
}

func (s *OrgService) DynamicAccessControlEnabled() bool {
	return s.Config.DynamicAccessControl != nil && s.Config.DynamicAccessControl.Enabled
}

// ─── Teams Operations ─────────────────────────────────────────────────────────

func (s *OrgService) CreateTeam(ctx context.Context, input dtos.CreateTeamInput, requestingUserID string) (*models.Team, error) {
	if !s.TeamsEnabled() {
		return nil, orgerrors.ErrTeamsDisabled
	}
	requester, err := s.memberRepo.GetMemberByOrgAndUser(ctx, input.OrganizationID, requestingUserID)
	if err != nil || !isAdminOrOwner(requester) {
		return nil, autherr.ErrForbidden
	}

	if s.Config.Teams.MaximumTeams != nil {
		_, total, err := s.teamRepo.ListTeamsByOrgID(ctx, input.OrganizationID, models.Pagination{})
		if err == nil && int(total) >= *s.Config.Teams.MaximumTeams {
			return nil, orgerrors.ErrMaximumTeamsReached
		}
	}

	now := coremodels.TimeNow()
	team := &models.Team{
		Base:           coremodels.Base{ID: coremodels.NewID(), CreatedAt: now, UpdatedAt: now},
		Name:           input.Name,
		OrganizationID: input.OrganizationID,
	}
	return s.teamRepo.CreateTeam(ctx, team)
}

func (s *OrgService) GetTeam(ctx context.Context, teamID string, requestingUserID string) (*models.Team, error) {
	if !s.TeamsEnabled() {
		return nil, orgerrors.ErrTeamsDisabled
	}
	team, err := s.teamRepo.GetTeamByID(ctx, teamID)
	if err != nil || team == nil {
		return nil, orgerrors.ErrTeamNotFound
	}
	m, err := s.memberRepo.GetMemberByOrgAndUser(ctx, team.OrganizationID, requestingUserID)
	if err != nil || m == nil {
		return nil, autherr.ErrForbidden
	}
	return team, nil
}

func (s *OrgService) UpdateTeam(ctx context.Context, input dtos.UpdateTeamInput, requestingUserID string) (*models.Team, error) {
	if !s.TeamsEnabled() {
		return nil, orgerrors.ErrTeamsDisabled
	}
	team, err := s.teamRepo.GetTeamByID(ctx, input.TeamID)
	if err != nil || team == nil {
		return nil, orgerrors.ErrTeamNotFound
	}
	requester, err := s.memberRepo.GetMemberByOrgAndUser(ctx, team.OrganizationID, requestingUserID)
	if err != nil || !isAdminOrOwner(requester) {
		return nil, autherr.ErrForbidden
	}
	return s.teamRepo.UpdateTeam(ctx, input.TeamID, map[string]interface{}{"Name": input.Name})
}

func (s *OrgService) DeleteTeam(ctx context.Context, input dtos.DeleteTeamInput, requestingUserID string) error {
	if !s.TeamsEnabled() {
		return orgerrors.ErrTeamsDisabled
	}
	team, err := s.teamRepo.GetTeamByID(ctx, input.TeamID)
	if err != nil || team == nil {
		return orgerrors.ErrTeamNotFound
	}
	requester, err := s.memberRepo.GetMemberByOrgAndUser(ctx, team.OrganizationID, requestingUserID)
	if err != nil || !isAdminOrOwner(requester) {
		return autherr.ErrForbidden
	}

	if !s.Config.Teams.AllowRemovingAllTeams {
		_, total, err := s.teamRepo.ListTeamsByOrgID(ctx, team.OrganizationID, models.Pagination{})
		if err == nil && total <= 1 {
			return orgerrors.ErrCannotRemoveAllTeams
		}
	}
	return s.teamRepo.DeleteTeam(ctx, input.TeamID)
}

func (s *OrgService) ListTeams(ctx context.Context, orgID string, requestingUserID string, pagi models.Pagination) ([]models.Team, int64, error) {
	if !s.TeamsEnabled() {
		return nil, 0, orgerrors.ErrTeamsDisabled
	}
	requester, err := s.memberRepo.GetMemberByOrgAndUser(ctx, orgID, requestingUserID)
	if err != nil || requester == nil {
		return nil, 0, autherr.ErrForbidden
	}
	return s.teamRepo.ListTeamsByOrgID(ctx, orgID, pagi)
}

func (s *OrgService) AddTeamMember(ctx context.Context, input dtos.AddTeamMemberInput, requestingUserID string) (*models.TeamMember, error) {
	if !s.TeamsEnabled() {
		return nil, orgerrors.ErrTeamsDisabled
	}
	team, err := s.teamRepo.GetTeamByID(ctx, input.TeamID)
	if err != nil || team == nil {
		return nil, orgerrors.ErrTeamNotFound
	}
	requester, err := s.memberRepo.GetMemberByOrgAndUser(ctx, team.OrganizationID, requestingUserID)
	if err != nil || !isAdminOrOwner(requester) {
		return nil, autherr.ErrForbidden
	}
	targetMember, err := s.memberRepo.GetMemberByOrgAndUser(ctx, team.OrganizationID, input.UserID)
	if err != nil || targetMember == nil {
		return nil, orgerrors.ErrMemberNotFound
	}
	existing, err := s.teamMemberRepo.GetTeamMember(ctx, input.TeamID, input.UserID)
	if err == nil && existing != nil {
		return nil, orgerrors.ErrAlreadyTeamMember
	}

	if s.Config.Teams.MaximumMembersPerTeam != nil {
		_, count, err := s.teamMemberRepo.ListMembersByTeamID(ctx, input.TeamID, models.Pagination{})
		if err == nil && int(count) >= *s.Config.Teams.MaximumMembersPerTeam {
			return nil, orgerrors.ErrMaximumTeamMembersReached
		}
	}

	now := coremodels.TimeNow()
	tm := &models.TeamMember{
		Base:   coremodels.Base{ID: coremodels.NewID(), CreatedAt: now, UpdatedAt: now},
		TeamID: input.TeamID,
		UserID: input.UserID,
	}
	return s.teamMemberRepo.CreateTeamMember(ctx, tm)
}

func (s *OrgService) RemoveTeamMember(ctx context.Context, input dtos.RemoveTeamMemberInput, requestingUserID string) error {
	if !s.TeamsEnabled() {
		return orgerrors.ErrTeamsDisabled
	}
	team, err := s.teamRepo.GetTeamByID(ctx, input.TeamID)
	if err != nil || team == nil {
		return orgerrors.ErrTeamNotFound
	}
	if requestingUserID != input.UserID {
		requester, err := s.memberRepo.GetMemberByOrgAndUser(ctx, team.OrganizationID, requestingUserID)
		if err != nil || !isAdminOrOwner(requester) {
			return autherr.ErrForbidden
		}
	}
	existing, err := s.teamMemberRepo.GetTeamMember(ctx, input.TeamID, input.UserID)
	if err != nil || existing == nil {
		return orgerrors.ErrTeamMemberNotFound
	}
	return s.teamMemberRepo.DeleteTeamMember(ctx, input.TeamID, input.UserID)
}

func (s *OrgService) ListTeamMembers(ctx context.Context, teamID string, requestingUserID string, pagi models.Pagination) ([]models.TeamMember, int64, error) {
	if !s.TeamsEnabled() {
		return nil, 0, orgerrors.ErrTeamsDisabled
	}
	team, err := s.teamRepo.GetTeamByID(ctx, teamID)
	if err != nil || team == nil {
		return nil, 0, orgerrors.ErrTeamNotFound
	}
	m, err := s.memberRepo.GetMemberByOrgAndUser(ctx, team.OrganizationID, requestingUserID)
	if err != nil || m == nil {
		return nil, 0, autherr.ErrForbidden
	}
	return s.teamMemberRepo.ListMembersByTeamID(ctx, teamID, pagi)
}

func (s *OrgService) SetActiveTeam(ctx context.Context, sessionID string, teamID *string, userID string) (*authdtos.SessionWithUser, error) {
	if !s.TeamsEnabled() {
		return nil, orgerrors.ErrTeamsDisabled
	}
	if teamID != nil && *teamID != "" {
		team, err := s.teamRepo.GetTeamByID(ctx, *teamID)
		if err != nil || team == nil {
			return nil, orgerrors.ErrTeamNotFound
		}
		tm, err := s.teamMemberRepo.GetTeamMember(ctx, *teamID, userID)
		if err != nil || tm == nil {
			return nil, autherr.ErrForbidden
		}
	}
	if s.sessionMgr == nil {
		return nil, autherr.New("INTERNAL_ERROR", "session manager not available", 500)
	}

	patch := config.SessionPatch{ActiveTeamID: teamID}
	var updatedSession *authdtos.SessionWithUser
	if sRepo, ok := s.userRepo.(repo_interfaces.ISessionRepo); ok && sessionID != "" {
		dbSess, err := sRepo.FindSessionByID(ctx, sessionID)
		if err == nil && dbSess != nil {
			sw, err := s.sessionMgr.Get(ctx, dbSess.Token)
			if err == nil && sw != nil {
				updatedSession, _ = s.sessionMgr.UpdatePatch(ctx, sw, patch)
			}
		}
	}
	if updatedSession == nil && sessionID != "" {
		sw, err := s.sessionMgr.Get(ctx, sessionID)
		if err == nil && sw != nil {
			updatedSession, _ = s.sessionMgr.UpdatePatch(ctx, sw, patch)
		}
	}
	if updatedSession == nil {
		return nil, autherr.ErrInvalidToken
	}
	return updatedSession, nil
}

// ─── Dynamic Access Control Operations ─────────────────────────────────────────

func (s *OrgService) CreateRole(ctx context.Context, orgID, role, permission, requestingUserID string) (*models.OrganizationRole, error) {
	if !s.DynamicAccessControlEnabled() {
		return nil, autherr.ErrForbidden
	}
	requester, err := s.memberRepo.GetMemberByOrgAndUser(ctx, orgID, requestingUserID)
	if err != nil || requester == nil || requester.Role != models.OrgRoleOwner {
		return nil, autherr.ErrForbidden
	}
	now := coremodels.TimeNow()
	r := &models.OrganizationRole{
		Base:           coremodels.Base{ID: coremodels.NewID(), CreatedAt: now, UpdatedAt: now},
		OrganizationID: orgID,
		Role:           role,
		Permission:     permission,
	}
	return s.orgRoleRepo.CreateRole(ctx, r)
}

func (s *OrgService) GetRole(ctx context.Context, orgID, role, requestingUserID string) (*models.OrganizationRole, error) {
	requester, err := s.memberRepo.GetMemberByOrgAndUser(ctx, orgID, requestingUserID)
	if err != nil || requester == nil {
		return nil, autherr.ErrForbidden
	}
	r, err := s.orgRoleRepo.GetRole(ctx, orgID, role)
	if err != nil || r == nil {
		return nil, orgerrors.ErrOrgRoleNotFound
	}
	return r, nil
}

func (s *OrgService) UpdateRole(ctx context.Context, orgID, role, permission, requestingUserID string) (*models.OrganizationRole, error) {
	if !s.DynamicAccessControlEnabled() {
		return nil, autherr.ErrForbidden
	}
	requester, err := s.memberRepo.GetMemberByOrgAndUser(ctx, orgID, requestingUserID)
	if err != nil || requester == nil || requester.Role != models.OrgRoleOwner {
		return nil, autherr.ErrForbidden
	}
	return s.orgRoleRepo.UpdateRole(ctx, orgID, role, permission)
}

func (s *OrgService) DeleteRole(ctx context.Context, orgID, role, requestingUserID string) error {
	if !s.DynamicAccessControlEnabled() {
		return autherr.ErrForbidden
	}
	requester, err := s.memberRepo.GetMemberByOrgAndUser(ctx, orgID, requestingUserID)
	if err != nil || requester == nil || requester.Role != models.OrgRoleOwner {
		return autherr.ErrForbidden
	}
	return s.orgRoleRepo.DeleteRole(ctx, orgID, role)
}

func (s *OrgService) ListRoles(ctx context.Context, orgID, requestingUserID string) ([]models.OrganizationRole, error) {
	requester, err := s.memberRepo.GetMemberByOrgAndUser(ctx, orgID, requestingUserID)
	if err != nil || requester == nil {
		return nil, autherr.ErrForbidden
	}
	return s.orgRoleRepo.ListRolesByOrgID(ctx, orgID)
}

func (s *OrgService) HasPermission(ctx context.Context, orgID, role, resource, action string) (bool, error) {
	if !s.DynamicAccessControlEnabled() {
		if role == string(models.OrgRoleOwner) {
			return true, nil
		}
		if role == string(models.OrgRoleAdmin) {
			if resource == "organization" && (action == "delete" || action == "update-role") {
				return false, nil
			}
			return true, nil
		}
		if role == string(models.OrgRoleMember) {
			return action == "read" || action == "list" || action == "get", nil
		}
		return false, nil
	}

	if s.orgRoleRepo == nil {
		return false, nil
	}
	r, err := s.orgRoleRepo.GetRole(ctx, orgID, role)
	if err != nil || r == nil {
		if role == string(models.OrgRoleOwner) {
			return true, nil
		}
		return false, nil
	}

	var permDoc map[string][]string
	if err := json.Unmarshal([]byte(r.Permission), &permDoc); err != nil {
		return false, fmt.Errorf("orgsvc: invalid permission json: %w", err)
	}

	if wildcardActions, ok := permDoc["*"]; ok {
		for _, a := range wildcardActions {
			if a == "*" || a == action {
				return true, nil
			}
		}
	}

	if actions, ok := permDoc[resource]; ok {
		for _, a := range actions {
			if a == "*" || a == action {
				return true, nil
			}
		}
	}

	return false, nil
}
