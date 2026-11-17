package orgsvc

import (
	"context"
	"strings"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
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
	// Step 1: Permission check - requester must be an organization admin/owner
	if !s.isOrgAdmin(ctx, input.OrganizationID, requestingUserID, "member", "delete") {
		return autherr.ErrForbidden
	}

	// Step 2: Fetch target member and validate it belongs to the organization
	target, err := s.memberRepo.GetMemberByID(ctx, input.MemberID)
	if err != nil || target.OrganizationID != input.OrganizationID {
		return orgerrors.ErrMemberNotFound
	}

	// Step 3: Organization owner cannot be removed
	if target.Role == models.OrgRoleOwner {
		return autherr.New("CANNOT_REMOVE_OWNER", "Cannot remove the organization owner", 400)
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

	// Step 2: If leaving member is an owner, ensure at least one other owner remains
	if member.Role == models.OrgRoleOwner {
		members, total, listErr := s.memberRepo.ListMembersByOrgID(ctx, orgID, models.Pagination{Limit: 1000})
		if listErr != nil {
			return listErr
		}
		hasOtherOwner := false
		for _, m := range members {
			if m.Role == models.OrgRoleOwner && m.UserID != userID {
				hasOtherOwner = true
				break
			}
		}
		// Check remaining pages if organization has more than 1000 members
		for offset := len(members); !hasOtherOwner && int64(offset) < total; {
			page, _, pageErr := s.memberRepo.ListMembersByOrgID(ctx, orgID, models.Pagination{Limit: 1000, Offset: offset})
			if pageErr != nil || len(page) == 0 {
				break
			}
			for _, m := range page {
				if m.Role == models.OrgRoleOwner && m.UserID != userID {
					hasOtherOwner = true
					break
				}
			}
			offset += len(page)
		}
		if !hasOtherOwner {
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

func isAdminOrOwner(m *models.Member) bool {
	return m != nil && (m.Role == models.OrgRoleOwner || m.Role == models.OrgRoleAdmin)
}
