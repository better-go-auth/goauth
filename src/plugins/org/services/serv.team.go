// Package orgsvc implements team and dynamic access control services.
package orgsvc

import (
	"context"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/config"
	coremodels "github.com/better-go-auth/goauth/src/models"
	authdtos "github.com/better-go-auth/goauth/src/models/dtos"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	"github.com/better-go-auth/goauth/src/plugins/org/dtos"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
	orgerrors "github.com/better-go-auth/goauth/src/plugins/org/org-errors"
	orgrepo "github.com/better-go-auth/goauth/src/plugins/org/repository"
)

// ─── Teams Operations ─────────────────────────────────────────────────────────

func (s *OrgService) CreateTeam(ctx context.Context, input dtos.CreateTeamInput, requestingUserID string) (*models.Team, error) {
	// Step 1: Verify teams are enabled in organization configuration
	if !s.TeamsEnabled() {
		return nil, orgerrors.ErrTeamsDisabled
	}

	// Step 2: Verify requesting user is an organization admin/owner
	if !s.isOrgAdmin(ctx, input.OrganizationID, requestingUserID, "team", "create") {
		return nil, autherr.ErrForbidden
	}

	// Step 3: Fetch requesting user and organization for limit and hook context
	var reqUser *coremodels.User
	if s.userRepo != nil && requestingUserID != "" {
		reqUser, _ = s.userRepo.FindUserByID(ctx, requestingUserID)
	}
	org, _ := s.orgRepo.GetOrgByID(ctx, input.OrganizationID)

	// Step 4: Check maximum teams limit
	if s.Config.Teams.MaximumTeams != nil {
		_, total, err := s.teamRepo.ListTeamsByOrgID(ctx, input.OrganizationID, models.Pagination{})
		if err == nil && int(total) >= *s.Config.Teams.MaximumTeams {
			return nil, orgerrors.ErrMaximumTeamsReached
		}
	}
	if s.Config.Teams.MaximumTeamsFn != nil {
		max, err := s.Config.Teams.MaximumTeamsFn(ctx, orgconfig.TeamLimitData{
			OrganizationID: input.OrganizationID,
			User:           reqUser,
		})
		if err != nil {
			return nil, err
		}
		if max > 0 {
			_, total, err := s.teamRepo.ListTeamsByOrgID(ctx, input.OrganizationID, models.Pagination{})
			if err == nil && int(total) >= max {
				return nil, orgerrors.ErrMaximumTeamsReached
			}
		}
	}

	// Step 5: Execute beforeCreateTeam lifecycle hook if configured
	if s.Config.OrganizationHooks.BeforeCreateTeam != nil {
		hookData := orgconfig.BeforeCreateTeamData{
			Team:         input,
			User:         reqUser,
			Organization: org,
		}
		override, err := s.Config.OrganizationHooks.BeforeCreateTeam(ctx, hookData)
		if err != nil {
			return nil, err
		}
		if override != nil {
			input = *override
		}
	}

	// Step 6: Construct and persist new team
	now := coremodels.TimeNow()
	team := &models.Team{
		Base:           coremodels.Base{ID: coremodels.NewID(), CreatedAt: now, UpdatedAt: now},
		Name:           input.Name,
		OrganizationID: input.OrganizationID,
	}
	created, err := s.teamRepo.CreateTeam(ctx, team)
	if err != nil {
		return nil, err
	}

	// Step 7: Execute afterCreateTeam lifecycle hook if configured
	if s.Config.OrganizationHooks.AfterCreateTeam != nil {
		_ = s.Config.OrganizationHooks.AfterCreateTeam(ctx, orgconfig.AfterCreateTeamData{
			Team:         created,
			User:         reqUser,
			Organization: org,
		})
	}

	return created, nil
}

func (s *OrgService) GetTeam(ctx context.Context, teamID string, requestingUserID string) (*models.Team, error) {
	// Step 1: Verify teams are enabled
	if !s.TeamsEnabled() {
		return nil, orgerrors.ErrTeamsDisabled
	}
	// Step 2: Load target team
	team, err := s.teamRepo.GetTeamByID(ctx, teamID)
	if err != nil || team == nil {
		return nil, orgerrors.ErrTeamNotFound
	}
	// Step 3: Verify requesting user is a member of the organization
	m, err := s.memberRepo.GetMemberByOrgAndUser(ctx, team.OrganizationID, requestingUserID)
	if err != nil || m == nil {
		return nil, autherr.ErrForbidden
	}
	return team, nil
}

func (s *OrgService) UpdateTeam(ctx context.Context, input dtos.UpdateTeamInput, requestingUserID string) (*models.Team, error) {
	// Step 1: Verify teams are enabled
	if !s.TeamsEnabled() {
		return nil, orgerrors.ErrTeamsDisabled
	}

	// Step 2: Fetch existing team
	team, err := s.teamRepo.GetTeamByID(ctx, input.TeamID)
	if err != nil || team == nil {
		return nil, orgerrors.ErrTeamNotFound
	}

	// Step 3: Verify requesting user is an organization admin/owner
	if !s.isOrgAdmin(ctx, team.OrganizationID, requestingUserID, "team", "update") {
		return nil, autherr.ErrForbidden
	}

	// Step 4: Fetch user and organization for hook context
	var reqUser *coremodels.User
	if s.userRepo != nil && requestingUserID != "" {
		reqUser, _ = s.userRepo.FindUserByID(ctx, requestingUserID)
	}
	org, _ := s.orgRepo.GetOrgByID(ctx, team.OrganizationID)

	// Step 5: Execute beforeUpdateTeam lifecycle hook if configured
	if s.Config.OrganizationHooks.BeforeUpdateTeam != nil {
		hookData := orgconfig.BeforeUpdateTeamData{
			Team:         team,
			Updates:      input,
			User:         reqUser,
			Organization: org,
		}
		override, err := s.Config.OrganizationHooks.BeforeUpdateTeam(ctx, hookData)
		if err != nil {
			return nil, err
		}
		if override != nil {
			input = *override
		}
	}

	// Step 6: Update team in repository
	updated, err := s.teamRepo.UpdateTeam(ctx, input.TeamID, map[string]interface{}{"Name": input.Name})
	if err != nil {
		return nil, err
	}

	// Step 7: Execute afterUpdateTeam lifecycle hook if configured
	if s.Config.OrganizationHooks.AfterUpdateTeam != nil {
		_ = s.Config.OrganizationHooks.AfterUpdateTeam(ctx, orgconfig.AfterUpdateTeamData{
			Team:         updated,
			User:         reqUser,
			Organization: org,
		})
	}

	return updated, nil
}

func (s *OrgService) DeleteTeam(ctx context.Context, input dtos.DeleteTeamInput, requestingUserID string) error {
	// Step 1: Verify teams are enabled
	if !s.TeamsEnabled() {
		return orgerrors.ErrTeamsDisabled
	}

	// Step 2: Fetch existing team
	team, err := s.teamRepo.GetTeamByID(ctx, input.TeamID)
	if err != nil || team == nil {
		return orgerrors.ErrTeamNotFound
	}

	// Step 3: Verify requesting user is an organization admin/owner
	if !s.isOrgAdmin(ctx, team.OrganizationID, requestingUserID, "team", "delete") {
		return autherr.ErrForbidden
	}

	// Step 4: Check if removing all teams is prohibited
	if !s.Config.Teams.AllowRemovingAllTeams {
		_, total, err := s.teamRepo.ListTeamsByOrgID(ctx, team.OrganizationID, models.Pagination{})
		if err == nil && total <= 1 {
			return orgerrors.ErrCannotRemoveAllTeams
		}
	}

	// Step 5: Fetch user and organization for hook context
	var reqUser *coremodels.User
	if s.userRepo != nil && requestingUserID != "" {
		reqUser, _ = s.userRepo.FindUserByID(ctx, requestingUserID)
	}
	org, _ := s.orgRepo.GetOrgByID(ctx, team.OrganizationID)

	// Step 6: Execute beforeDeleteTeam lifecycle hook if configured
	if s.Config.OrganizationHooks.BeforeDeleteTeam != nil {
		if err := s.Config.OrganizationHooks.BeforeDeleteTeam(ctx, orgconfig.BeforeDeleteTeamData{
			Team:         team,
			User:         reqUser,
			Organization: org,
		}); err != nil {
			return err
		}
	}

	// Step 7: Delete team from repository
	if err := s.teamRepo.DeleteTeam(ctx, input.TeamID); err != nil {
		return err
	}

	// Step 8: Execute afterDeleteTeam lifecycle hook if configured
	if s.Config.OrganizationHooks.AfterDeleteTeam != nil {
		_ = s.Config.OrganizationHooks.AfterDeleteTeam(ctx, orgconfig.AfterDeleteTeamData{
			Team:         team,
			User:         reqUser,
			Organization: org,
		})
	}

	return nil
}

func (s *OrgService) ListTeams(ctx context.Context, orgID string, requestingUserID string, pagi models.Pagination) ([]models.Team, int64, error) {
	// Step 1: Verify teams are enabled
	if !s.TeamsEnabled() {
		return nil, 0, orgerrors.ErrTeamsDisabled
	}
	// Step 2: Verify requesting user is a member of the organization
	requester, err := s.memberRepo.GetMemberByOrgAndUser(ctx, orgID, requestingUserID)
	if err != nil || requester == nil {
		return nil, 0, autherr.ErrForbidden
	}
	return s.teamRepo.ListTeamsByOrgID(ctx, orgID, pagi)
}

func (s *OrgService) AddTeamMember(ctx context.Context, input dtos.AddTeamMemberInput, requestingUserID string) (*models.TeamMember, error) {
	// Step 1: Verify teams are enabled
	if !s.TeamsEnabled() {
		return nil, orgerrors.ErrTeamsDisabled
	}

	// Step 2: Fetch existing team
	team, err := s.teamRepo.GetTeamByID(ctx, input.TeamID)
	if err != nil || team == nil {
		return nil, orgerrors.ErrTeamNotFound
	}

	// Step 3: Verify requesting user is an organization admin/owner
	if !s.isOrgAdmin(ctx, team.OrganizationID, requestingUserID, "member", "update") {
		return nil, autherr.ErrForbidden
	}

	// Step 4: Ensure target user is a member of the organization
	targetMember, err := s.memberRepo.GetMemberByOrgAndUser(ctx, team.OrganizationID, input.UserID)
	if err != nil || targetMember == nil {
		return nil, orgerrors.ErrUserNotMemberOfOrg400
	}

	// Step 5: better-auth's findOrCreateTeamMember: an existing membership is returned as is
	existing, err := s.teamMemberRepo.GetTeamMember(ctx, input.TeamID, input.UserID)
	if err == nil && existing != nil {
		return existing, nil
	}

	// Step 6: Fetch user and organization for limit and hook context
	var reqUser *coremodels.User
	if s.userRepo != nil && requestingUserID != "" {
		reqUser, _ = s.userRepo.FindUserByID(ctx, requestingUserID)
	}
	org, _ := s.orgRepo.GetOrgByID(ctx, team.OrganizationID)

	// Step 7: Check maximum members per team limit
	if s.Config.Teams.MaximumMembersPerTeam != nil {
		_, count, err := s.teamMemberRepo.ListMembersByTeamID(ctx, input.TeamID, models.Pagination{})
		if err == nil && int(count) >= *s.Config.Teams.MaximumMembersPerTeam {
			return nil, orgerrors.ErrMaximumTeamMembersReached
		}
	}
	if s.Config.Teams.MaximumMembersPerTeamFn != nil {
		max, err := s.Config.Teams.MaximumMembersPerTeamFn(ctx, orgconfig.TeamMemberLimitData{
			TeamID:         input.TeamID,
			OrganizationID: team.OrganizationID,
			User:           reqUser,
		})
		if err != nil {
			return nil, err
		}
		if max > 0 {
			_, count, err := s.teamMemberRepo.ListMembersByTeamID(ctx, input.TeamID, models.Pagination{})
			if err == nil && int(count) >= max {
				return nil, orgerrors.ErrMaximumTeamMembersReached
			}
		}
	}

	// Step 8: Execute beforeAddTeamMember lifecycle hook if configured
	if s.Config.OrganizationHooks.BeforeAddTeamMember != nil {
		hookData := orgconfig.BeforeAddTeamMemberData{
			TeamMember:   input,
			Team:         team,
			User:         reqUser,
			Organization: org,
		}
		override, err := s.Config.OrganizationHooks.BeforeAddTeamMember(ctx, hookData)
		if err != nil {
			return nil, err
		}
		if override != nil {
			input = *override
		}
	}

	// Step 9: Construct and persist new team member
	now := coremodels.TimeNow()
	tm := &models.TeamMember{
		Base:   coremodels.Base{ID: coremodels.NewID(), CreatedAt: now, UpdatedAt: now},
		TeamID: input.TeamID,
		UserID: input.UserID,
	}
	created, err := s.teamMemberRepo.CreateTeamMember(ctx, tm)
	if err != nil {
		return nil, err
	}

	// Step 10: Execute afterAddTeamMember lifecycle hook if configured
	if s.Config.OrganizationHooks.AfterAddTeamMember != nil {
		_ = s.Config.OrganizationHooks.AfterAddTeamMember(ctx, orgconfig.AfterAddTeamMemberData{
			TeamMember:   created,
			Team:         team,
			User:         reqUser,
			Organization: org,
		})
	}

	return created, nil
}

func (s *OrgService) RemoveTeamMember(ctx context.Context, input dtos.RemoveTeamMemberInput, requestingUserID string) error {
	// Step 1: Verify teams are enabled
	if !s.TeamsEnabled() {
		return orgerrors.ErrTeamsDisabled
	}

	// Step 2: Fetch existing team
	team, err := s.teamRepo.GetTeamByID(ctx, input.TeamID)
	if err != nil || team == nil {
		return orgerrors.ErrTeamNotFound
	}

	// Step 3: Permission check - user can remove themselves or an org admin/owner can remove
	if requestingUserID != input.UserID {
		if !s.isOrgAdmin(ctx, team.OrganizationID, requestingUserID, "member", "delete") {
			return autherr.ErrForbidden
		}
	}

	// Step 4: Verify existing team member record
	existing, err := s.teamMemberRepo.GetTeamMember(ctx, input.TeamID, input.UserID)
	if err != nil || existing == nil {
		return orgerrors.ErrTeamMemberNotFound
	}

	// Step 5: Fetch user and organization for hook context
	var reqUser *coremodels.User
	if s.userRepo != nil && requestingUserID != "" {
		reqUser, _ = s.userRepo.FindUserByID(ctx, requestingUserID)
	}
	org, _ := s.orgRepo.GetOrgByID(ctx, team.OrganizationID)

	// Step 6: Execute beforeRemoveTeamMember lifecycle hook if configured
	if s.Config.OrganizationHooks.BeforeRemoveTeamMember != nil {
		if err := s.Config.OrganizationHooks.BeforeRemoveTeamMember(ctx, orgconfig.BeforeRemoveTeamMemberData{
			TeamMember:   existing,
			Team:         team,
			User:         reqUser,
			Organization: org,
		}); err != nil {
			return err
		}
	}

	// Step 7: Delete team member from repository
	if err := s.teamMemberRepo.DeleteTeamMember(ctx, input.TeamID, input.UserID); err != nil {
		return err
	}

	// Step 8: Execute afterRemoveTeamMember lifecycle hook if configured
	if s.Config.OrganizationHooks.AfterRemoveTeamMember != nil {
		_ = s.Config.OrganizationHooks.AfterRemoveTeamMember(ctx, orgconfig.AfterRemoveTeamMemberData{
			TeamMember:   existing,
			Team:         team,
			User:         reqUser,
			Organization: org,
		})
	}

	return nil
}

func (s *OrgService) ListTeamMembers(ctx context.Context, teamID string, requestingUserID string, pagi models.Pagination) ([]models.TeamMember, int64, error) {
	// Step 1: Verify teams are enabled
	if !s.TeamsEnabled() {
		return nil, 0, orgerrors.ErrTeamsDisabled
	}
	// Step 2: Load target team
	team, err := s.teamRepo.GetTeamByID(ctx, teamID)
	if err != nil || team == nil {
		return nil, 0, orgerrors.ErrTeamNotFound
	}
	// Step 3: Verify requesting user is a member of the organization and of the team
	// (better-auth answers 400 USER_IS_NOT_A_MEMBER_OF_THE_TEAM for both)
	m, err := s.memberRepo.GetMemberByOrgAndUser(ctx, team.OrganizationID, requestingUserID)
	if err != nil || m == nil {
		return nil, 0, orgerrors.ErrTeamMemberNotFound
	}
	if tm, err := s.teamMemberRepo.GetTeamMember(ctx, teamID, requestingUserID); err != nil || tm == nil {
		return nil, 0, orgerrors.ErrTeamMemberNotFound
	}
	return s.teamMemberRepo.ListMembersByTeamID(ctx, teamID, pagi)
}

// ListUserTeams returns the teams userID belongs to, limited to organizations the user is still a member
// of (better-auth's /organization/list-user-teams).
func (s *OrgService) ListUserTeams(ctx context.Context, userID string) ([]models.Team, error) {
	// Step 1: Verify teams are enabled
	if !s.TeamsEnabled() {
		return nil, orgerrors.ErrTeamsDisabled
	}
	// Step 2: the user's organizations (membership filter, like better-auth's checkMembership)
	orgs, err := s.orgRepo.ListOrgsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	memberOf := make(map[string]bool, len(orgs))
	for _, o := range orgs {
		memberOf[o.ID] = true
	}
	// Step 3: the user's teams, in one query when the repository supports it
	var teams []models.Team
	if lister, ok := s.teamMemberRepo.(orgrepo.IUserTeamsLister); ok {
		if teams, err = lister.ListTeamsByUserID(ctx, userID); err != nil {
			return nil, err
		}
	} else {
		for _, o := range orgs {
			orgTeams, _, err := s.teamRepo.ListTeamsByOrgID(ctx, o.ID, models.Pagination{Limit: 1000})
			if err != nil {
				return nil, err
			}
			for _, t := range orgTeams {
				if tm, err := s.teamMemberRepo.GetTeamMember(ctx, t.ID, userID); err == nil && tm != nil {
					teams = append(teams, t)
				}
			}
		}
	}
	// Step 4: drop teams of organizations the user left
	out := make([]models.Team, 0, len(teams))
	for _, t := range teams {
		if memberOf[t.OrganizationID] {
			out = append(out, t)
		}
	}
	return out, nil
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
			return nil, orgerrors.ErrUserNotMemberOfTeam403
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
