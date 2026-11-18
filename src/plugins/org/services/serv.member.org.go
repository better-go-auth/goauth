package orgsvc

import (
	"context"
	"strings"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	coremodels "github.com/better-go-auth/goauth/src/models"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	"github.com/better-go-auth/goauth/src/plugins/org/dtos"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
	orgerrors "github.com/better-go-auth/goauth/src/plugins/org/org-errors"
)

// ─── Members ──────────────────────────────────────────────────────────────────

func (s *OrgService) GetMember(ctx context.Context, orgID, userID string) (*models.Member, error) {
	member, err := s.memberRepo.GetMemberByOrgAndUser(ctx, orgID, userID)
	if err != nil {
		return nil, orgerrors.ErrMemberNotFound
	}
	return member, nil
}

func (s *OrgService) GetMemberByID(ctx context.Context, memberID string) (*models.Member, error) {
	member, err := s.memberRepo.GetMemberByID(ctx, memberID)
	if err != nil || member == nil {
		return nil, orgerrors.ErrMemberNotFound
	}
	return member, nil
}

// ResolveMemberID resolves either a member ID or user email into a member ID for the given organization.
func (s *OrgService) ResolveMemberID(ctx context.Context, orgID, memberIDOrEmail string) (string, error) {
	// Step 1: Check if memberIDOrEmail matches a member ID directly in the target organization
	if m, err := s.memberRepo.GetMemberByID(ctx, memberIDOrEmail); err == nil && m != nil && m.OrganizationID == orgID {
		return m.ID, nil
	}
	// Step 2: Otherwise treat as email and look up user + membership
	if s.userRepo != nil {
		if u, err := s.userRepo.FindUserByEmail(ctx, strings.ToLower(strings.TrimSpace(memberIDOrEmail))); err == nil && u != nil {
			if m, err := s.memberRepo.GetMemberByOrgAndUser(ctx, orgID, u.ID); err == nil && m != nil {
				return m.ID, nil
			}
		}
	}
	return "", orgerrors.ErrMemberNotFound
}

func (s *OrgService) ListMembers(ctx context.Context, orgID string, pagi models.Pagination) ([]models.Member, int64, error) {
	return s.memberRepo.ListMembersByOrgID(ctx, orgID, pagi)
}

func (s *OrgService) UpdateMemberRole(ctx context.Context, input dtos.UpdateMemberRoleInput, requestingUserID string) (*models.Member, error) {
	// Step 1: Fetch target member to be updated
	target, err := s.memberRepo.GetMemberByID(ctx, input.MemberID)
	if err != nil || target == nil {
		return nil, orgerrors.ErrMemberNotFound
	}
	if input.OrganizationID == "" {
		input.OrganizationID = target.OrganizationID
	}

	// Step 1b: better-auth's update-member-role rules (only when the update is made by a member)
	if requestingUserID != "" {
		if err := s.checkMemberRoleUpdate(ctx, input, target, requestingUserID); err != nil {
			return nil, err
		}
	}

	// Step 2: Fetch requesting user and organization for hook context
	var reqUser *coremodels.User
	if s.userRepo != nil && requestingUserID != "" {
		reqUser, _ = s.userRepo.FindUserByID(ctx, requestingUserID)
	}
	org, _ := s.orgRepo.GetOrgByID(ctx, target.OrganizationID)
	prevRole := string(target.Role)

	// Step 3: Execute beforeUpdateMemberRole lifecycle hook if configured
	if s.Config.OrganizationHooks.BeforeUpdateMemberRole != nil {
		hookData := orgconfig.BeforeUpdateMemberRoleData{
			Member:       target,
			NewRole:      string(input.Role),
			User:         reqUser,
			Organization: org,
		}
		override, err := s.Config.OrganizationHooks.BeforeUpdateMemberRole(ctx, hookData)
		if err != nil {
			return nil, err
		}
		if override != nil {
			input.Role = models.OrgMemberRole(*override)
		}
	}

	// Step 4: Update member role in repository
	updated, err := s.memberRepo.UpdateMember(ctx, input.MemberID, map[string]interface{}{"Role": string(input.Role)})
	if err != nil {
		return nil, err
	}

	// Step 5: Execute afterUpdateMemberRole lifecycle hook if configured
	if s.Config.OrganizationHooks.AfterUpdateMemberRole != nil {
		_ = s.Config.OrganizationHooks.AfterUpdateMemberRole(ctx, orgconfig.AfterUpdateMemberRoleData{
			Member:       updated,
			PreviousRole: prevRole,
			User:         reqUser,
			Organization: org,
		})
	}

	return updated, nil
}

func (s *OrgService) RemoveMember(ctx context.Context, input dtos.RemoveMemberInput, requestingUserID string) error {
	// Step 1: the requester must be a member
	requester, err := s.memberRepo.GetMemberByOrgAndUser(ctx, input.OrganizationID, requestingUserID)
	if err != nil || requester == nil {
		return orgerrors.ErrMemberNotFound
	}

	// Step 2: Fetch target member
	target, err := s.memberRepo.GetMemberByID(ctx, input.MemberID)
	if err != nil || target == nil {
		return orgerrors.ErrMemberNotFound
	}

	// Step 3: like better-auth, an owner (creator role) can only be removed by an owner, and never the last one
	creatorRole := s.CreatorRole()
	if HasRole(string(target.Role), creatorRole) {
		if !HasRole(string(requester.Role), creatorRole) {
			return orgerrors.ErrCannotLeaveAsSoleOwner
		}
		owners, err := s.countRoleHolders(ctx, input.OrganizationID, creatorRole)
		if err != nil {
			return err
		}
		if owners <= 1 {
			return orgerrors.ErrCannotLeaveAsSoleOwner
		}
	}

	// Step 3b: Permission check - member:delete (better-auth answers 401 YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER)
	if !s.isOrgAdmin(ctx, input.OrganizationID, requestingUserID, "member", "delete") {
		return orgerrors.ErrNotAllowedToDeleteMember
	}
	// Step 3c: the target must belong to the organization
	if target.OrganizationID != input.OrganizationID {
		return orgerrors.ErrMemberNotFound
	}

	// Step 4: Fetch requesting user and organization for hook context
	var reqUser *coremodels.User
	if s.userRepo != nil && requestingUserID != "" {
		reqUser, _ = s.userRepo.FindUserByID(ctx, requestingUserID)
	}
	org, _ := s.orgRepo.GetOrgByID(ctx, input.OrganizationID)

	// Step 5: Execute beforeRemoveMember lifecycle hook if configured
	if s.Config.OrganizationHooks.BeforeRemoveMember != nil {
		if err := s.Config.OrganizationHooks.BeforeRemoveMember(ctx, orgconfig.BeforeRemoveMemberData{
			Member:       target,
			User:         reqUser,
			Organization: org,
		}); err != nil {
			return err
		}
	}

	// Step 6: Delete member from repository
	if err := s.memberRepo.DeleteMemberByID(ctx, input.MemberID); err != nil {
		return err
	}

	// Step 7: Execute afterRemoveMember lifecycle hook if configured
	if s.Config.OrganizationHooks.AfterRemoveMember != nil {
		_ = s.Config.OrganizationHooks.AfterRemoveMember(ctx, orgconfig.AfterRemoveMemberData{
			Member:       target,
			User:         reqUser,
			Organization: org,
		})
	}

	return nil
}

// LeaveOrganization allows an authenticated member to voluntarily leave an organization.
// Sole owners are blocked with ErrCannotLeaveAsSoleOwner; active session org context is cleared if it matched.
func (s *OrgService) LeaveOrganization(ctx context.Context, orgID, userID, sessionID string) error {
	// Step 1: Verify caller is currently a member of the organization
	member, err := s.memberRepo.GetMemberByOrgAndUser(ctx, orgID, userID)
	if err != nil || member == nil {
		return orgerrors.ErrMemberNotFound
	}

	// Step 2: If leaving member is an owner (creator role, multi-role aware), ensure at least one other owner remains
	if HasRole(string(member.Role), s.CreatorRole()) {
		owners, err := s.countRoleHolders(ctx, orgID, s.CreatorRole())
		if err != nil {
			return err
		}
		if owners <= 1 {
			return orgerrors.ErrCannotLeaveAsSoleOwner
		}
	}

	// Step 3: Fetch user and organization for hook context
	var reqUser *coremodels.User
	if s.userRepo != nil && userID != "" {
		reqUser, _ = s.userRepo.FindUserByID(ctx, userID)
	}
	org, _ := s.orgRepo.GetOrgByID(ctx, orgID)

	// Step 4: Execute beforeRemoveMember lifecycle hook if configured
	if s.Config.OrganizationHooks.BeforeRemoveMember != nil {
		if err := s.Config.OrganizationHooks.BeforeRemoveMember(ctx, orgconfig.BeforeRemoveMemberData{
			Member:       member,
			User:         reqUser,
			Organization: org,
		}); err != nil {
			return err
		}
	}

	// Step 5: Delete caller's membership record
	if err := s.memberRepo.DeleteMemberByID(ctx, member.ID); err != nil {
		return err
	}

	// Step 6: Clear ActiveOrganizationID on session if it currently points to the left organization
	if sessionID != "" {
		shouldClear := false
		if sRepo, ok := s.userRepo.(repo_interfaces.ISessionRepo); ok {
			if dbSess, err := sRepo.FindSessionByID(ctx, sessionID); err == nil && dbSess != nil {
				if dbSess.ActiveOrganizationID != nil && *dbSess.ActiveOrganizationID == orgID {
					shouldClear = true
				}
			}
		}
		if !shouldClear && s.sessionMgr != nil {
			if sw, err := s.sessionMgr.Get(ctx, sessionID); err == nil && sw != nil {
				if sw.Session.ActiveOrganizationID != nil && *sw.Session.ActiveOrganizationID == orgID {
					shouldClear = true
				}
			}
		}
		if shouldClear {
			_, _ = s.SetActiveOrganization(ctx, sessionID, nil, userID, "")
		}
	}

	// Step 7: Execute afterRemoveMember lifecycle hook if configured
	if s.Config.OrganizationHooks.AfterRemoveMember != nil {
		_ = s.Config.OrganizationHooks.AfterRemoveMember(ctx, orgconfig.AfterRemoveMemberData{
			Member:       member,
			User:         reqUser,
			Organization: org,
		})
	}

	return nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// CreatorRole returns the role given to organization creators (Config.CreatorRole, default "owner").
func (s *OrgService) CreatorRole() string {
	if s.Config.CreatorRole != "" {
		return s.Config.CreatorRole
	}
	return models.OrgRoleOwner.Str()
}

// HasRole reports whether the comma-separated member role contains role (better-auth's role.split(",")).
func HasRole(memberRole, role string) bool {
	for _, r := range strings.Split(memberRole, ",") {
		if strings.TrimSpace(r) == role {
			return true
		}
	}
	return false
}

// checkMemberRoleUpdate applies better-auth's update-member-role rules: the target must belong to the
// organization, only an owner (creator role) may change an owner or grant the owner role, and the last owner
// cannot remove the role from themselves.
func (s *OrgService) checkMemberRoleUpdate(ctx context.Context, input dtos.UpdateMemberRoleInput, target *models.Member, requestingUserID string) error {
	// Step 1: the updater must be a member of the organization
	updater, err := s.memberRepo.GetMemberByOrgAndUser(ctx, input.OrganizationID, requestingUserID)
	if err != nil || updater == nil {
		return orgerrors.ErrMemberNotFound
	}
	// Step 2: the target must be in the same organization
	if target.OrganizationID != input.OrganizationID {
		return orgerrors.ErrNotAllowedToUpdateMember
	}
	// Step 3: owner-related rules
	creatorRole := s.CreatorRole()
	updaterIsCreator := HasRole(string(updater.Role), creatorRole)
	isUpdatingCreator := HasRole(string(target.Role), creatorRole)
	isSettingCreatorRole := HasRole(string(input.Role), creatorRole)
	if (isUpdatingCreator || isSettingCreatorRole) && !updaterIsCreator {
		return orgerrors.ErrNotAllowedToUpdateMember
	}
	// Step 4: the last owner cannot drop the owner role from themselves
	if updaterIsCreator && updater.ID == target.ID && !isSettingCreatorRole {
		owners, err := s.countRoleHolders(ctx, input.OrganizationID, creatorRole)
		if err != nil {
			return err
		}
		if owners <= 1 {
			return orgerrors.ErrCannotLeaveWithoutOwner
		}
	}
	return nil
}

// countRoleHolders counts the members of orgID holding role, paging through large organizations.
func (s *OrgService) countRoleHolders(ctx context.Context, orgID, role string) (int, error) {
	count := 0
	for offset := 0; ; {
		// Step 1: load one page of members
		page, total, err := s.memberRepo.ListMembersByOrgID(ctx, orgID, models.Pagination{Limit: 1000, Offset: offset})
		if err != nil {
			return 0, err
		}
		// Step 2: count the role holders on the page
		for _, m := range page {
			if HasRole(string(m.Role), role) {
				count++
			}
		}
		// Step 3: stop after the last page
		offset += len(page)
		if len(page) == 0 || int64(offset) >= total {
			return count, nil
		}
	}
}

func isAdminOrOwner(m *models.Member) bool {
	return m != nil && (m.Role == models.OrgRoleOwner || m.Role == models.OrgRoleAdmin)
}
