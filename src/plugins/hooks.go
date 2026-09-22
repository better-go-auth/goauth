package plugins

import (
	"context"
	"sync"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/providers/token"
)

// HookService defines the hook lifecycle methods that a plugin or service can implement.
// A plugin can implement this interface and register it with the HookRegistry as a whole,
// instead of binding separate callbacks on init.
type HookService interface {
	BeforeUserCreate(ctx context.Context, user *models.User) error
	AfterUserCreate(ctx context.Context, user *models.User) error
	UserDeleted(ctx context.Context, userID string) error
	UserBanned(ctx context.Context, userID string, reason *string) error
	BeforeSessionCreate(ctx context.Context, session *models.Session, claims *token.CustomClaims) error
	SessionRevoked(ctx context.Context, sessionID string) error
	ActiveOrgChanged(ctx context.Context, userID, newOrgID string) error
}

// DefaultHookService provides a default no-op implementation of HookService.
// Embed this struct in your plugin's hook service so you only need to implement the hooks you care about.
// Any hook that is not implemented simply returns nil.
type DefaultHookService struct{}

func (DefaultHookService) BeforeUserCreate(ctx context.Context, user *models.User) error {
	return nil
}

func (DefaultHookService) AfterUserCreate(ctx context.Context, user *models.User) error {
	return nil
}

func (DefaultHookService) UserDeleted(ctx context.Context, userID string) error {
	return nil
}

func (DefaultHookService) UserBanned(ctx context.Context, userID string, reason *string) error {
	return nil
}

func (DefaultHookService) BeforeSessionCreate(ctx context.Context, session *models.Session, claims *token.CustomClaims) error {
	return nil
}

func (DefaultHookService) SessionRevoked(ctx context.Context, sessionID string) error {
	return nil
}

func (DefaultHookService) ActiveOrgChanged(ctx context.Context, userID, newOrgID string) error {
	return nil
}

// HookRegistry defines the registration and dispatch interface for auth lifecycle events.
type HookRegistry interface {
	// Register appends a HookService implementation to the registry.
	Register(service HookService)
	// Append is an alias for Register.
	Append(service HookService)

	// Subscriptions for ad-hoc individual callbacks
	// Use these for quick one-time hooks instead of implementing the full HookService interface
	// mostly useful for testing and quick integration of this library to your app
	OnBeforeUserCreate(fn func(ctx context.Context, user *models.User) error)
	OnAfterUserCreate(fn func(ctx context.Context, user *models.User) error)
	OnUserDeleted(fn func(ctx context.Context, userID string) error)
	OnUserBanned(fn func(ctx context.Context, userID string, reason *string) error)
	OnBeforeSessionCreate(fn func(ctx context.Context, session *models.Session, claims *token.CustomClaims) error)
	OnSessionRevoked(fn func(ctx context.Context, sessionID string) error)
	OnActiveOrgChanged(fn func(ctx context.Context, userID, newOrgID string) error)

	// Triggers
	TriggerBeforeUserCreate(ctx context.Context, user *models.User) error
	TriggerAfterUserCreate(ctx context.Context, user *models.User) error
	TriggerUserDeleted(ctx context.Context, userID string) error
	TriggerUserBanned(ctx context.Context, userID string, reason *string) error
	TriggerBeforeSessionCreate(ctx context.Context, session *models.Session, claims *token.CustomClaims) error
	TriggerSessionRevoked(ctx context.Context, sessionID string) error
	TriggerActiveOrgChanged(ctx context.Context, userID, newOrgID string) error
}

// DefaultHookRegistry provides thread-safe lifecycle hook registration and dispatch.
type DefaultHookRegistry struct {
	mu       sync.RWMutex
	services []HookService

	beforeUserCreate    []func(ctx context.Context, user *models.User) error
	afterUserCreate     []func(ctx context.Context, user *models.User) error
	userDeleted         []func(ctx context.Context, userID string) error
	userBanned          []func(ctx context.Context, userID string, reason *string) error
	beforeSessionCreate []func(ctx context.Context, session *models.Session, claims *token.CustomClaims) error
	sessionRevoked      []func(ctx context.Context, sessionID string) error
	activeOrgChanged    []func(ctx context.Context, userID, newOrgID string) error
}

// NewHookRegistry creates a new HookRegistry instance.
func NewHookRegistry() HookRegistry {
	return &DefaultHookRegistry{}
}

func (h *DefaultHookRegistry) Register(service HookService) {
	if service == nil {
		return
	}
	if h.services == nil {
		h.services = make([]HookService, 0)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, existing := range h.services {
		if existing == service {
			return
		}
	}
	h.services = append(h.services, service)
}

func (h *DefaultHookRegistry) Append(service HookService) {
	h.Register(service)
}

func (h *DefaultHookRegistry) OnBeforeUserCreate(fn func(ctx context.Context, user *models.User) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beforeUserCreate = append(h.beforeUserCreate, fn)
}

func (h *DefaultHookRegistry) OnAfterUserCreate(fn func(ctx context.Context, user *models.User) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.afterUserCreate = append(h.afterUserCreate, fn)
}

func (h *DefaultHookRegistry) OnUserDeleted(fn func(ctx context.Context, userID string) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.userDeleted = append(h.userDeleted, fn)
}

func (h *DefaultHookRegistry) OnUserBanned(fn func(ctx context.Context, userID string, reason *string) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.userBanned = append(h.userBanned, fn)
}

func (h *DefaultHookRegistry) OnBeforeSessionCreate(fn func(ctx context.Context, session *models.Session, claims *token.CustomClaims) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beforeSessionCreate = append(h.beforeSessionCreate, fn)
}

func (h *DefaultHookRegistry) OnSessionRevoked(fn func(ctx context.Context, sessionID string) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sessionRevoked = append(h.sessionRevoked, fn)
}

func (h *DefaultHookRegistry) OnActiveOrgChanged(fn func(ctx context.Context, userID, newOrgID string) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.activeOrgChanged = append(h.activeOrgChanged, fn)
}

func (h *DefaultHookRegistry) TriggerBeforeUserCreate(ctx context.Context, user *models.User) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, s := range h.services {
		if err := s.BeforeUserCreate(ctx, user); err != nil {
			return err
		}
	}
	for _, fn := range h.beforeUserCreate {
		if err := fn(ctx, user); err != nil {
			return err
		}
	}
	return nil
}

func (h *DefaultHookRegistry) TriggerAfterUserCreate(ctx context.Context, user *models.User) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, s := range h.services {
		if err := s.AfterUserCreate(ctx, user); err != nil {
			return err
		}
	}
	for _, fn := range h.afterUserCreate {
		if err := fn(ctx, user); err != nil {
			return err
		}
	}
	return nil
}

func (h *DefaultHookRegistry) TriggerUserDeleted(ctx context.Context, userID string) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, s := range h.services {
		if err := s.UserDeleted(ctx, userID); err != nil {
			return err
		}
	}
	for _, fn := range h.userDeleted {
		if err := fn(ctx, userID); err != nil {
			return err
		}
	}
	return nil
}

func (h *DefaultHookRegistry) TriggerUserBanned(ctx context.Context, userID string, reason *string) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, s := range h.services {
		if err := s.UserBanned(ctx, userID, reason); err != nil {
			return err
		}
	}
	for _, fn := range h.userBanned {
		if err := fn(ctx, userID, reason); err != nil {
			return err
		}
	}
	return nil
}

func (h *DefaultHookRegistry) TriggerBeforeSessionCreate(ctx context.Context, session *models.Session, claims *token.CustomClaims) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, s := range h.services {
		if err := s.BeforeSessionCreate(ctx, session, claims); err != nil {
			return err
		}
	}
	for _, fn := range h.beforeSessionCreate {
		if err := fn(ctx, session, claims); err != nil {
			return err
		}
	}
	return nil
}

func (h *DefaultHookRegistry) TriggerSessionRevoked(ctx context.Context, sessionID string) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, s := range h.services {
		if err := s.SessionRevoked(ctx, sessionID); err != nil {
			return err
		}
	}
	for _, fn := range h.sessionRevoked {
		if err := fn(ctx, sessionID); err != nil {
			return err
		}
	}
	return nil
}

func (h *DefaultHookRegistry) TriggerActiveOrgChanged(ctx context.Context, userID, newOrgID string) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, s := range h.services {
		if err := s.ActiveOrgChanged(ctx, userID, newOrgID); err != nil {
			return err
		}
	}
	for _, fn := range h.activeOrgChanged {
		if err := fn(ctx, userID, newOrgID); err != nil {
			return err
		}
	}
	return nil
}
