package orgsvc

import (
	"context"
	"fmt"
	"strings"
	"time"

	autherr "github.com/better-go-auth/goauth/src/common/errors"
	coremodels "github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins/org/dtos"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
	orgerrors "github.com/better-go-auth/goauth/src/plugins/org/org-errors"
)

// ─── Invitations ─────────────────────────────────────────────────────────────

func (s *OrgService) InviteMember(ctx context.Context, inviterID string, input dtos.InviteMemberInput) (*models.Invitation, error) {
	// Check inviter is admin or owner
	inviter, err := s.memberRepo.GetMemberByOrgAndUser(ctx, input.OrganizationID, inviterID)
	if err != nil || !isAdminOrOwner(inviter) {
		return nil, autherr.ErrForbidden
	}

	// Check if user is already a member
	user, _ := s.userRepo.GetUserByEmail(ctx, strings.ToLower(input.Email))
	if user != nil {
		if m, err := s.memberRepo.GetMemberByOrgAndUser(ctx, input.OrganizationID, user.ID); err == nil && m != nil {
			return nil, orgerrors.ErrAlreadyMember
		}
	}

	// Cancel any existing pending invite and create new invite inside a transaction
	var created *models.Invitation
	err = s.txManager.Transaction(ctx, func(txCtx context.Context) error {
		if existing, err := s.inviteRepo.GetInvitationByOrgAndEmail(txCtx, input.OrganizationID, input.Email); err == nil && existing != nil {
			_, err = s.inviteRepo.UpdateInvitation(txCtx, existing.ID, map[string]interface{}{"status": string(models.InvitationCanceled)})
			if err != nil {
				return fmt.Errorf("orgsvc: cancel existing invitation: %w", err)
			}
		}

		now := new(time.Now())
		inv := &models.Invitation{
			Base:           coremodels.Base{ID: coremodels.NewID(), CreatedAt: now, UpdatedAt: now},
			OrganizationID: input.OrganizationID,
			InviterID:      inviterID,
			Email:          strings.ToLower(input.Email),
			Role:           input.Role,
			Status:         models.InvitationPending,
			ExpiresAt:      time.Now().UTC().Add(48 * time.Hour),
		}
		var err error
		created, err = s.inviteRepo.CreateInvitation(txCtx, inv)
		if err != nil {
			return fmt.Errorf("orgsvc: create invitation: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Send invitation email
	if s.Config.SendOrgInvitation != nil {
		inviterUser, _ := s.userRepo.GetUserByID(ctx, inviterID)
		org, _ := s.orgRepo.GetOrgByID(ctx, input.OrganizationID)
		inviterName := ""
		orgName := ""
		if inviterUser != nil {
			inviterName = inviterUser.GetFullname()
		}
		if org != nil {
			orgName = org.Name
		}
		inviteURL := fmt.Sprintf("%s%s/organization/accept-invitation?invitationId=%s", s.Cfg.BaseURL, s.Cfg.BasePath, created.ID)
		go func() {
			_ = s.Config.SendOrgInvitation(context.Background(), input.Email, inviterName, orgName, inviteURL)
		}()
	}
	return created, nil
}

func (s *OrgService) GetInvitation(ctx context.Context, invitationID string) (*models.Invitation, error) {
	inv, err := s.inviteRepo.GetInvitationByID(ctx, invitationID)
	if err != nil {
		return nil, orgerrors.ErrInvitationNotFound
	}
	return inv, nil
}

func (s *OrgService) AcceptInvitation(ctx context.Context, invitationID, userID string) error {
	inv, err := s.inviteRepo.GetInvitationByID(ctx, invitationID)
	if err != nil || inv == nil {
		return orgerrors.ErrInvitationNotFound
	}
	if inv.Status != models.InvitationPending {
		return autherr.New("INVITATION_ALREADY_USED", "This invitation has already been used", 400)
	}
	if time.Now().After(inv.ExpiresAt) {
		return orgerrors.ErrInvitationExpired
	}

	// Verify accepting user's email matches the invite
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return autherr.ErrUserNotFound
	}
	if user.Email == nil || !strings.EqualFold(*user.Email, inv.Email) {
		return autherr.ErrForbidden
	}

	// Add as member and update invitation status inside a transaction
	err = s.txManager.Transaction(ctx, func(txCtx context.Context) error {
		now := new(time.Now().UTC())
		member := &models.Member{
			Base:           coremodels.Base{ID: coremodels.NewID(), CreatedAt: now, UpdatedAt: now},
			OrganizationID: inv.OrganizationID,
			UserID:         userID,
			Role:           inv.Role,
		}
		if _, err := s.memberRepo.CreateMember(txCtx, member); err != nil {
			return fmt.Errorf("orgsvc: add member on accept: %w", err)
		}

		// Update invitation status
		acceptedAt := time.Now().UTC()
		_, err = s.inviteRepo.UpdateInvitation(txCtx, invitationID, map[string]interface{}{
			"status":         string(models.InvitationAccepted),
			"accepted_by_id": userID,
			"accepted_at":    acceptedAt,
		})
		if err != nil {
			return fmt.Errorf("orgsvc: update invitation status: %w", err)
		}
		return nil
	})

	return err
}

func (s *OrgService) RejectInvitation(ctx context.Context, invitationID, userID string) error {
	inv, err := s.inviteRepo.GetInvitationByID(ctx, invitationID)
	if err != nil {
		return orgerrors.ErrInvitationNotFound
	}
	user, _ := s.userRepo.GetUserByID(ctx, userID)
	if user == nil || !strings.EqualFold(user.GetEmail(), inv.Email) {
		return autherr.ErrForbidden
	}
	_, err = s.inviteRepo.UpdateInvitation(ctx, invitationID, map[string]interface{}{"status": string(models.InvitationRejected)})
	return err
}

func (s *OrgService) CancelInvitation(ctx context.Context, invitationID, requestingUserID string) error {
	inv, err := s.inviteRepo.GetInvitationByID(ctx, invitationID)
	if err != nil {
		return orgerrors.ErrInvitationNotFound
	}
	// Only admin/owner of the org can cancel
	member, err := s.memberRepo.GetMemberByOrgAndUser(ctx, inv.OrganizationID, requestingUserID)
	if err != nil || !isAdminOrOwner(member) {
		return autherr.ErrForbidden
	}
	_, err = s.inviteRepo.UpdateInvitation(ctx, invitationID, map[string]interface{}{"status": string(models.InvitationCanceled)})
	return err
}

func (s *OrgService) ListInvitations(ctx context.Context, orgID string, pagi models.Pagination) ([]models.Invitation, int64, error) {
	return s.inviteRepo.ListInvitationsByOrgID(ctx, orgID, pagi)
}
