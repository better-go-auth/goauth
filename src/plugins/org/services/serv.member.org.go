package orgsvc

import (
	"context"

	autherr "github.com/better-go-auth/goauth/src/common/errors"
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

func (s *OrgService) ListMembers(ctx context.Context, orgID string, pagi models.Pagination) ([]models.Member, int64, error) {
	return s.memberRepo.ListMembersByOrgID(ctx, orgID, pagi)
}

func (s *OrgService) UpdateMemberRole(ctx context.Context, input dtos.UpdateMemberRoleInput, requestingUserID string) (*models.Member, error) {
	// Check requester is admin or owner
	requester, err := s.memberRepo.GetMemberByOrgAndUser(ctx, input.OrganizationID, requestingUserID)
	if err != nil || !isAdminOrOwner(requester) {
		return nil, autherr.ErrForbidden
	}
	// Cannot demote the owner
	target, err := s.memberRepo.GetMemberByID(ctx, input.MemberID)
	if err != nil {
		return nil, orgerrors.ErrMemberNotFound
	}
	if target.Role == models.OrgRoleOwner && input.Role != models.OrgRoleOwner {
		return nil, autherr.New("CANNOT_DEMOTE_OWNER", "Cannot change the owner's role", 400)
	}
	return s.memberRepo.UpdateMember(ctx, input.MemberID, map[string]interface{}{"role": string(input.Role)})
}

func (s *OrgService) RemoveMember(ctx context.Context, input dtos.RemoveMemberInput, requestingUserID string) error {
	requester, err := s.memberRepo.GetMemberByOrgAndUser(ctx, input.OrganizationID, requestingUserID)
	if err != nil || !isAdminOrOwner(requester) {
		return autherr.ErrForbidden
	}
	target, err := s.memberRepo.GetMemberByID(ctx, input.MemberID)
	if err != nil {
		return orgerrors.ErrMemberNotFound
	}
	if target.Role == models.OrgRoleOwner {
		return autherr.New("CANNOT_REMOVE_OWNER", "Cannot remove the organization owner", 400)
	}
	return s.memberRepo.DeleteMemberByID(ctx, input.MemberID)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func isAdminOrOwner(m *models.Member) bool {
	return m != nil && (m.Role == models.OrgRoleOwner || m.Role == models.OrgRoleAdmin)
}
