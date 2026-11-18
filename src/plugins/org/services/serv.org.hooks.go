package orgsvc

import (
	"context"

	"github.com/better-go-auth/goauth/src/plugins"
	orgrepo "github.com/better-go-auth/goauth/src/plugins/org/repository"
)

// OrgHookService implements plugins.HookService for the organization plugin.
// It embeds plugins.DefaultHookService so any unhandled hook returns nil.
type OrgHookService struct {
	plugins.DefaultHookService
	orgRepo    orgrepo.IOrgRepo
	memberRepo orgrepo.IMemberRepo
	// optional cleaners for the other rows that reference the user (see WithUserCleanup)
	teamMembers orgrepo.IUserTeamMembersCleaner
	invitations orgrepo.IInviterInvitationsCleaner
}

// WithUserCleanup lets UserDeleted also remove the user's team memberships and the invitations they sent,
// when the given repositories support it (the GORM ones do).
func (h *OrgHookService) WithUserCleanup(invitations orgrepo.IInvitationRepo, teamMembers orgrepo.ITeamMemberRepo) *OrgHookService {
	if c, ok := invitations.(orgrepo.IInviterInvitationsCleaner); ok {
		h.invitations = c
	}
	if c, ok := teamMembers.(orgrepo.IUserTeamMembersCleaner); ok {
		h.teamMembers = c
	}
	return h
}

// NewOrgHookService creates a new OrgHookService.
func NewOrgHookService(orgRepo orgrepo.IOrgRepo, memberRepo orgrepo.IMemberRepo) *OrgHookService {
	return &OrgHookService{
		orgRepo:    orgRepo,
		memberRepo: memberRepo,
	}
}

// UserDeleted removes every org row that references the deleted user, like better-auth's onDelete: "cascade"
// (with the default hard delete the user row is removed after this hook, so nothing may still point at it).
func (h *OrgHookService) UserDeleted(ctx context.Context, userID string) error {
	// Step 1: team memberships
	if h.teamMembers != nil {
		_ = h.teamMembers.DeleteTeamMembersByUserID(ctx, userID)
	}
	// Step 2: invitations the user sent
	if h.invitations != nil {
		_ = h.invitations.DeleteInvitationsByInviterID(ctx, userID)
	}
	// Step 3: memberships in every organization
	orgs, err := h.orgRepo.ListOrgsByUserID(ctx, userID)
	if err == nil {
		for _, o := range orgs {
			_ = h.memberRepo.DeleteMemberByOrgAndUser(ctx, o.ID, userID)
		}
	}
	return nil
}
