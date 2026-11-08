package orgsvc

import (
	"context"

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
	// Step 1: Permission check - requester must be system admin or organization admin/owner
	if !s.isSystemAdminOrOrgAdmin(ctx, input.OrganizationID, requestingUserID) {
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

// ─── Helpers ──────────────────────────────────────────────────────────────────

func isAdminOrOwner(m *models.Member) bool {
	return m != nil && (m.Role == models.OrgRoleOwner || m.Role == models.OrgRoleAdmin)
}
