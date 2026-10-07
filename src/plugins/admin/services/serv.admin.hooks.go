package services

import (
	"context"
	"time"

	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/admin/repository"
	"github.com/better-go-auth/goauth/src/providers/token"
)

// AdminHookService implements plugins.HookService for the admin plugin.
// It embeds plugins.DefaultHookService so any unhandled hook returns nil.
type AdminHookService struct {
	plugins.DefaultHookService
	adminRepo repository.IAdminRepo
}

// NewAdminHookService creates a new AdminHookService.
func NewAdminHookService(adminRepo repository.IAdminRepo) *AdminHookService {
	return &AdminHookService{
		adminRepo: adminRepo,
	}
}

// BeforeSessionCreate is better-auth's admin session.create.before hook: banned users get no session,
// and a ban whose BanExpires has passed is lifted instead.
func (h *AdminHookService) BeforeSessionCreate(ctx context.Context, session *models.Session, _ *token.CustomClaims) error {
	user, err := h.adminRepo.GetUserByID(ctx, session.UserID)
	if err != nil || user == nil || !user.Banned {
		return nil
	}
	if user.BanExpires != nil && !user.BanExpires.After(time.Now()) {
		_, err := h.adminRepo.UnbanUser(ctx, user.ID)
		return err
	}
	return autherr.ErrBannedUser
}
