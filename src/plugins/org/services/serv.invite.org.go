package orgsvc

import (
	"context"
	"fmt"
	"strings"
	"time"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	coremodels "github.com/better-go-auth/goauth/src/models"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	"github.com/better-go-auth/goauth/src/plugins/org/dtos"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
	orgerrors "github.com/better-go-auth/goauth/src/plugins/org/org-errors"
)

// ─── Invitations ─────────────────────────────────────────────────────────────

func (s *OrgService) InviteMember(ctx context.Context, inviterID string, input dtos.InviteMemberInput) (*models.Invitation, error) {
	// Step 1: Ensure organization exists and is active (pending or suspended orgs cannot invite members)
	org, err := s.orgRepo.GetOrgByID(ctx, input.OrganizationID)
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

	// Step 2: Fetch inviter user and member details for context
	var inviterUser *coremodels.User
	if s.userRepo != nil && inviterID != "" {
		inviterUser, _ = s.userRepo.FindUserByID(ctx, inviterID)
	}
	inviterMember, _ := s.memberRepo.GetMemberByOrgAndUser(ctx, input.OrganizationID, inviterID)

	// Step 3: Execute beforeCreateInvitation lifecycle hook if configured
	if s.Config.OrganizationHooks.BeforeCreateInvitation != nil {
		hookData := orgconfig.BeforeCreateInvitationData{
			Invitation:   input,
			Inviter:      inviterUser,
			Organization: org,
		}
		override, err := s.Config.OrganizationHooks.BeforeCreateInvitation(ctx, hookData)
		if err != nil {
			return nil, err
		}
		if override != nil {
			input = *override
		}
	}

	// Step 4: Check organization membership limit
	_, memberCount, err := s.memberRepo.ListMembersByOrgID(ctx, input.OrganizationID, models.Pagination{})
	if err == nil {
		limit := 100 // default 100
		if s.Config.MembershipLimit != nil {
			limit = *s.Config.MembershipLimit
		}
		if s.Config.MembershipLimitFn != nil {
			fnLimit, err := s.Config.MembershipLimitFn(ctx, inviterUser, org)
			if err != nil {
				return nil, err
			}
			limit = fnLimit
		}
		if limit > 0 && int(memberCount) >= limit {
			return nil, orgerrors.ErrMembershipLimitReached
		}
	}

	// Step 5: Check invitation limit
	_, invCount, err := s.inviteRepo.ListInvitationsByOrgID(ctx, input.OrganizationID, models.Pagination{})
	if err == nil {
		limit := 100 // default 100
		if s.Config.InvitationLimit != nil {
			limit = *s.Config.InvitationLimit
		}
		if s.Config.InvitationLimitFn != nil {
			fnLimit, err := s.Config.InvitationLimitFn(ctx, orgconfig.InvitationLimitData{
				User:         inviterUser,
				Organization: org,
				Member:       inviterMember,
			})
			if err != nil {
				return nil, err
			}
			limit = fnLimit
		}
		if limit > 0 && int(invCount) >= limit {
			return nil, orgerrors.ErrInvitationLimitReached
		}
	}

	// Step 6: Check if user is already a member
	user, _ := s.userRepo.FindUserByEmail(ctx, strings.ToLower(input.Email))
	if user != nil {
		if m, err := s.memberRepo.GetMemberByOrgAndUser(ctx, input.OrganizationID, user.ID); err == nil && m != nil {
			return nil, orgerrors.ErrAlreadyMember
		}
	}

	// Step 7: Handle existing pending invitation according to CancelPendingInvitationsOnReInvite
	var created *models.Invitation
	err = s.txManager.Transaction(ctx, func(txCtx context.Context) error {
		if existing, err := s.inviteRepo.GetInvitationByOrgAndEmail(txCtx, input.OrganizationID, input.Email); err == nil && existing != nil && existing.Status == models.InvitationPending {
			cancelOnReInvite := false
			if s.Config.CancelPendingInvitationsOnReInvite != nil {
				cancelOnReInvite = *s.Config.CancelPendingInvitationsOnReInvite
			}
			if cancelOnReInvite {
				_, err = s.inviteRepo.UpdateInvitation(txCtx, existing.ID, map[string]interface{}{"Status": string(models.InvitationCanceled)})
				if err != nil {
					return fmt.Errorf("orgsvc: cancel existing invitation: %w", err)
				}
			} else {
				return orgerrors.ErrPendingInvitationExists
			}
		}

		// Step 8: Calculate expiration duration using InvitationExpiresIn (default 48 hours)
		expiresIn := 48 * time.Hour
		if s.Config.InvitationExpiresIn > 0 {
			expiresIn = s.Config.InvitationExpiresIn
		}

		now := time.Now().UTC()
		var teamID *string
		if s.TeamsEnabled() && input.TeamID != nil && *input.TeamID != "" {
			teamID = input.TeamID
		}
		inv := &models.Invitation{
			Base:           coremodels.Base{ID: coremodels.NewID(), CreatedAt: now, UpdatedAt: now},
			OrganizationID: input.OrganizationID,
			InviterID:      inviterID,
			Email:          strings.ToLower(input.Email),
			Role:           input.Role,
			TeamID:         teamID,
			Status:         models.InvitationPending,
			ExpiresAt:      now.Add(expiresIn),
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

	// Step 9: Execute afterCreateInvitation lifecycle hook if configured
	if s.Config.OrganizationHooks.AfterCreateInvitation != nil {
		_ = s.Config.OrganizationHooks.AfterCreateInvitation(ctx, orgconfig.AfterCreateInvitationData{
			Invitation:   created,
			Inviter:      inviterUser,
			Organization: org,
		})
	}

	// Step 10: Send invitation email using configured email sender
	inviterMemberVal := models.Member{}
	if inviterMember != nil {
		inviterMemberVal = *inviterMember
	}
	if s.Config.SendInvitationEmail != nil {
		_ = s.Config.SendInvitationEmail(ctx, orgconfig.SendInvitationInput{
			ID:           created.ID,
			Role:         string(created.Role),
			Email:        created.Email,
			Organization: *org,
			Invitation:   *created,
			Inviter:      inviterMemberVal,
			InviterUser:  inviterUser,
		})
	} else if s.Config.SendOrgInvitation != nil {
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

// UserEmail returns the email of userID (empty when the user has none).
func (s *OrgService) UserEmail(ctx context.Context, userID string) (string, error) {
	user, err := s.userRepo.FindUserByID(ctx, userID)
	if err != nil || user == nil {
		return "", autherr.ErrUserNotFound
	}
	return user.GetEmail(), nil
}

func (s *OrgService) GetInvitation(ctx context.Context, invitationID string) (*models.Invitation, error) {
	inv, err := s.inviteRepo.GetInvitationByID(ctx, invitationID)
	if err != nil {
		return nil, orgerrors.ErrInvitationNotFound
	}
	return inv, nil
}

// GetInvitationForUser fetches an invitation and enforces RequireEmailVerificationOnInvitation when applicable.
func (s *OrgService) GetInvitationForUser(ctx context.Context, invitationID, requestingUserID string) (*models.Invitation, error) {
	// Step 1: Fetch invitation record
	inv, err := s.inviteRepo.GetInvitationByID(ctx, invitationID)
	if err != nil || inv == nil {
		return nil, orgerrors.ErrInvitationNotFound
	}
	// Step 2: Check email verification requirement if caller is the recipient
	if s.Config.RequireEmailVerificationOnInvitation && s.userRepo != nil && requestingUserID != "" {
		if user, err := s.userRepo.FindUserByID(ctx, requestingUserID); err == nil && user != nil {
			if strings.EqualFold(user.Email, inv.Email) && !user.EmailVerified {
				return nil, orgerrors.ErrEmailVerificationRequired
			}
		}
	}
	return inv, nil
}

func (s *OrgService) AcceptInvitation(ctx context.Context, invitationID, userID string) error {
	// Step 1: Fetch invitation and validate pending status and expiration
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

	// Step 2: Fetch accepting user and verify email
	user, err := s.userRepo.FindUserByID(ctx, userID)
	if err != nil {
		return autherr.ErrUserNotFound
	}
	if user.Email == "" || !strings.EqualFold(user.Email, inv.Email) {
		return autherr.ErrForbidden
	}

	// Step 3: Require email verification on invitation if enabled in config
	if s.Config.RequireEmailVerificationOnInvitation && !user.EmailVerified {
		return orgerrors.ErrEmailVerificationRequired
	}

	// Step 4: Fetch organization details
	org, err := s.orgRepo.GetOrgByID(ctx, inv.OrganizationID)
	if err != nil || org == nil {
		return orgerrors.ErrOrgNotFound
	}

	// Step 5: Check membership limit before admitting new member
	_, memberCount, err := s.memberRepo.ListMembersByOrgID(ctx, inv.OrganizationID, models.Pagination{})
	if err == nil {
		limit := 100
		if s.Config.MembershipLimit != nil {
			limit = *s.Config.MembershipLimit
		}
		if s.Config.MembershipLimitFn != nil {
			fnLimit, err := s.Config.MembershipLimitFn(ctx, user, org)
			if err != nil {
				return err
			}
			limit = fnLimit
		}
		if limit > 0 && int(memberCount) >= limit {
			return orgerrors.ErrMembershipLimitReached
		}
	}

	// Step 6: Execute beforeAcceptInvitation lifecycle hook if configured
	if s.Config.OrganizationHooks.BeforeAcceptInvitation != nil {
		if err := s.Config.OrganizationHooks.BeforeAcceptInvitation(ctx, orgconfig.BeforeAcceptInvitationData{
			Invitation:   inv,
			User:         user,
			Organization: org,
		}); err != nil {
			return err
		}
	}

	// Step 7: Prepare member record and execute beforeAddMember hook if configured
	now := time.Now().UTC()
	member := &models.Member{
		Base:           coremodels.Base{ID: coremodels.NewID(), CreatedAt: now, UpdatedAt: now},
		OrganizationID: inv.OrganizationID,
		UserID:         userID,
		Role:           inv.Role,
	}
	if s.Config.OrganizationHooks.BeforeAddMember != nil {
		override, err := s.Config.OrganizationHooks.BeforeAddMember(ctx, orgconfig.BeforeAddMemberData{
			Member:       *member,
			User:         user,
			Organization: org,
		})
		if err != nil {
			return err
		}
		if override != nil {
			member = override
		}
	}

	// Step 8: Add member and update invitation status inside a transaction
	var createdMember *models.Member
	err = s.txManager.Transaction(ctx, func(txCtx context.Context) error {
		var err error
		createdMember, err = s.memberRepo.CreateMember(txCtx, member)
		if err != nil {
			return fmt.Errorf("orgsvc: add member on accept: %w", err)
		}

		// Step 8b: If invitation includes a TeamID and teams are enabled, add member to that team
		if s.TeamsEnabled() && inv.TeamID != nil && *inv.TeamID != "" && s.teamMemberRepo != nil {
			tmNow := time.Now().UTC()
			_, _ = s.teamMemberRepo.CreateTeamMember(txCtx, &models.TeamMember{
				Base:   coremodels.Base{ID: coremodels.NewID(), CreatedAt: tmNow, UpdatedAt: tmNow},
				TeamID: *inv.TeamID,
				UserID: userID,
			})
		}

		// Update invitation status
		acceptedAt := time.Now().UTC()
		_, err = s.inviteRepo.UpdateInvitation(txCtx, invitationID, map[string]interface{}{
			"Status":       string(models.InvitationAccepted),
			"AcceptedByID": userID,
			"AcceptedAt":   acceptedAt,
		})
		if err != nil {
			return fmt.Errorf("orgsvc: update invitation status: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Step 9: Execute afterAddMember lifecycle hook if configured
	if s.Config.OrganizationHooks.AfterAddMember != nil {
		_ = s.Config.OrganizationHooks.AfterAddMember(ctx, orgconfig.AfterAddMemberData{
			Member:       createdMember,
			User:         user,
			Organization: org,
		})
	}

	// Step 10: Execute afterAcceptInvitation lifecycle hook if configured
	if s.Config.OrganizationHooks.AfterAcceptInvitation != nil {
		_ = s.Config.OrganizationHooks.AfterAcceptInvitation(ctx, orgconfig.AfterAcceptInvitationData{
			Invitation:   inv,
			Member:       createdMember,
			User:         user,
			Organization: org,
		})
	}

	return nil
}

func (s *OrgService) RejectInvitation(ctx context.Context, invitationID string, requestingUserID string) error {
	// Step 1: Fetch invitation
	inv, err := s.inviteRepo.GetInvitationByID(ctx, invitationID)
	if err != nil || inv == nil {
		return orgerrors.ErrInvitationNotFound
	}

	// Step 2: Fetch requesting user if available
	var user *coremodels.User
	if s.userRepo != nil && requestingUserID != "" {
		user, _ = s.userRepo.FindUserByID(ctx, requestingUserID)
	}

	// Step 3: Require email verification on invitation if enabled in config
	if s.Config.RequireEmailVerificationOnInvitation && user != nil && !user.EmailVerified {
		return orgerrors.ErrEmailVerificationRequired
	}

	// Step 4: Fetch organization for hook context
	org, _ := s.orgRepo.GetOrgByID(ctx, inv.OrganizationID)

	// Step 5: Execute beforeRejectInvitation lifecycle hook if configured
	if s.Config.OrganizationHooks.BeforeRejectInvitation != nil {
		if err := s.Config.OrganizationHooks.BeforeRejectInvitation(ctx, orgconfig.BeforeRejectInvitationData{
			Invitation:   inv,
			User:         user,
			Organization: org,
		}); err != nil {
			return err
		}
	}

	// Step 6: Update invitation status to rejected
	if _, err := s.inviteRepo.UpdateInvitation(ctx, invitationID, map[string]interface{}{"Status": string(models.InvitationRejected)}); err != nil {
		return err
	}

	// Step 7: Execute afterRejectInvitation lifecycle hook if configured
	if s.Config.OrganizationHooks.AfterRejectInvitation != nil {
		_ = s.Config.OrganizationHooks.AfterRejectInvitation(ctx, orgconfig.AfterRejectInvitationData{
			Invitation:   inv,
			User:         user,
			Organization: org,
		})
	}

	return nil
}

func (s *OrgService) CancelInvitation(ctx context.Context, invitationID string, requestingUserID string) error {
	// Step 1: Fetch invitation
	inv, err := s.inviteRepo.GetInvitationByID(ctx, invitationID)
	if err != nil || inv == nil {
		return orgerrors.ErrInvitationNotFound
	}

	// Step 2: Fetch cancelling user and organization details
	var user *coremodels.User
	if s.userRepo != nil && requestingUserID != "" {
		user, _ = s.userRepo.FindUserByID(ctx, requestingUserID)
	}
	org, _ := s.orgRepo.GetOrgByID(ctx, inv.OrganizationID)

	// Step 3: Execute beforeCancelInvitation lifecycle hook if configured
	if s.Config.OrganizationHooks.BeforeCancelInvitation != nil {
		if err := s.Config.OrganizationHooks.BeforeCancelInvitation(ctx, orgconfig.BeforeCancelInvitationData{
			Invitation:   inv,
			CancelledBy:  user,
			Organization: org,
		}); err != nil {
			return err
		}
	}

	// Step 4: Update invitation status to canceled
	if _, err := s.inviteRepo.UpdateInvitation(ctx, invitationID, map[string]interface{}{"Status": string(models.InvitationCanceled)}); err != nil {
		return err
	}

	// Step 5: Execute afterCancelInvitation lifecycle hook if configured
	if s.Config.OrganizationHooks.AfterCancelInvitation != nil {
		_ = s.Config.OrganizationHooks.AfterCancelInvitation(ctx, orgconfig.AfterCancelInvitationData{
			Invitation:   inv,
			CancelledBy:  user,
			Organization: org,
		})
	}

	return nil
}

func (s *OrgService) ListInvitations(ctx context.Context, orgID string, pagi models.Pagination) ([]models.Invitation, int64, error) {
	return s.inviteRepo.ListInvitationsByOrgID(ctx, orgID, pagi)
}
