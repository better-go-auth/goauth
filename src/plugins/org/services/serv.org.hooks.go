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
}

// NewOrgHookService creates a new OrgHookService.
func NewOrgHookService(orgRepo orgrepo.IOrgRepo, memberRepo orgrepo.IMemberRepo) *OrgHookService {
	return &OrgHookService{
		orgRepo:    orgRepo,
		memberRepo: memberRepo,
	}
}

// UserDeleted handles user deletion by removing their memberships in all organizations.
func (h *OrgHookService) UserDeleted(ctx context.Context, userID string) error {
	orgs, err := h.orgRepo.ListOrgsByUserID(ctx, userID)
	if err == nil {
		for _, o := range orgs {
			_ = h.memberRepo.DeleteMemberByOrgAndUser(ctx, o.ID, userID)
		}
	}
	return nil
}
