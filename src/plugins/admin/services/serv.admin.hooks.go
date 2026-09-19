package services

import (
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/admin/repository"
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
