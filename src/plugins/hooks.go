package plugins

import (
	"context"
	"net/http"
	"sync"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/providers/token"
)

// SignInEvent describes a completed credential sign-in (/sign-in/email, /sign-in/phone-number, ...)
// right after its session was created and before the response is written.
type SignInEvent struct {
	// Path is the sign-in endpoint path relative to BasePath (e.g. "/sign-in/email").
	Path string
	// Session is the session the sign-in created (and its user).
	Session *dtos.SessionWithUser
	// DontRemember is set for rememberMe=false sign-ins.
	DontRemember bool
	// Request is the incoming HTTP request (cookies of the browser), nil outside HTTP.
	Request *http.Request
}

// SignInChallenge replaces a sign-in response, like better-auth's two-factor after-hook returning
// {"twoFactorRedirect": true}. The interceptor is responsible for revoking ev.Session when it no longer applies.
type SignInChallenge struct {
	// Body is written as the JSON response body instead of {token, user}.
	Body any
	// Cookies are set instead of the session cookies.
	Cookies []http.Cookie
	// ExtraCookies are added to the normal sign-in response when Body is nil: the interceptor lets the
	// sign-in through but still sets cookies (e.g. two-factor rotating its trust_device cookie).
	ExtraCookies []http.Cookie
}

// Replaces reports whether the challenge replaces the sign-in response (a non-nil Body).
// A challenge with only ExtraCookies keeps the normal {token, user} response.
func (c *SignInChallenge) Replaces() bool { return c != nil && c.Body != nil }

// Extra returns the cookies to add to a normal sign-in response (nil-safe).
func (c *SignInChallenge) Extra() []http.Cookie {
	if c == nil || c.Body != nil {
		return nil
	}
	return c.ExtraCookies
}

// SignInInterceptor inspects a completed sign-in; returning a non-nil challenge replaces the response.
type SignInInterceptor func(ctx context.Context, ev SignInEvent) (*SignInChallenge, error)

// HookService defines the hook lifecycle methods that a plugin or service can implement.
// A plugin can implement this interface and register it with the HookRegistry as a whole,
// instead of binding separate callbacks on init.
type HookService interface {
	BeforeUserCreate(ctx context.Context, user *models.User) error
	AfterUserCreate(ctx context.Context, user *models.User) error
	UserDeleted(ctx context.Context, userID string) error
	UserBanned(ctx context.Context, userID string, reason *string) error
	BeforeSessionCreate(ctx context.Context, session *models.Session, claims *token.CustomClaims) error
	SessionRevoked(ctx context.Context, session *models.Session) error
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

func (DefaultHookService) SessionRevoked(ctx context.Context, session *models.Session) error {
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
	OnSessionRevoked(fn func(ctx context.Context, session *models.Session) error)
	OnActiveOrgChanged(fn func(ctx context.Context, userID, newOrgID string) error)
	// OnAfterSignIn registers a sign-in interceptor (e.g. the two-factor challenge).
	OnAfterSignIn(fn SignInInterceptor)

	// Triggers
	TriggerBeforeUserCreate(ctx context.Context, user *models.User) error
	TriggerAfterUserCreate(ctx context.Context, user *models.User) error
	TriggerUserDeleted(ctx context.Context, userID string) error
	TriggerUserBanned(ctx context.Context, userID string, reason *string) error
	TriggerBeforeSessionCreate(ctx context.Context, session *models.Session, claims *token.CustomClaims) error
	TriggerSessionRevoked(ctx context.Context, session *models.Session) error
	TriggerActiveOrgChanged(ctx context.Context, userID, newOrgID string) error
	// TriggerAfterSignIn runs the sign-in interceptors in order; the first non-nil challenge wins.
	TriggerAfterSignIn(ctx context.Context, ev SignInEvent) (*SignInChallenge, error)

	// Verification Override allows plugins (e.g. email-otp) to suppress or replace the core default verification email.
	OverrideEmailVerification()
	SetVerificationEmailSender(fn VerificationEmailSender)
	IsEmailVerificationOverridden() bool
	VerificationEmailSender() VerificationEmailSender
}

// VerificationEmailSender defines an overridden email verification dispatcher (e.g. sending an OTP instead of a link).
type VerificationEmailSender func(ctx context.Context, user *models.User, callbackURL string) error

// DefaultHookRegistry provides thread-safe lifecycle hook registration and dispatch.
type DefaultHookRegistry struct {
	mu       sync.RWMutex
	services []HookService

	emailVerificationOverridden bool
	verificationEmailSender     VerificationEmailSender

	beforeUserCreate    []func(ctx context.Context, user *models.User) error
	afterUserCreate     []func(ctx context.Context, user *models.User) error
	userDeleted         []func(ctx context.Context, userID string) error
	userBanned          []func(ctx context.Context, userID string, reason *string) error
	beforeSessionCreate []func(ctx context.Context, session *models.Session, claims *token.CustomClaims) error
	sessionRevoked      []func(ctx context.Context, session *models.Session) error
	activeOrgChanged    []func(ctx context.Context, userID, newOrgID string) error
	afterSignIn         []SignInInterceptor
}

// NewHookRegistry creates a new HookRegistry instance.
func NewHookRegistry() HookRegistry {
	return &DefaultHookRegistry{}
}

func (h *DefaultHookRegistry) OverrideEmailVerification() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.emailVerificationOverridden = true
}

func (h *DefaultHookRegistry) SetVerificationEmailSender(fn VerificationEmailSender) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.emailVerificationOverridden = true
	h.verificationEmailSender = fn
}

func (h *DefaultHookRegistry) IsEmailVerificationOverridden() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.emailVerificationOverridden
}

func (h *DefaultHookRegistry) VerificationEmailSender() VerificationEmailSender {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.verificationEmailSender
}

func (h *DefaultHookRegistry) Register(service HookService) {
	if service == nil {
		return
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

func (h *DefaultHookRegistry) OnSessionRevoked(fn func(ctx context.Context, session *models.Session) error) {
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

func (h *DefaultHookRegistry) TriggerSessionRevoked(ctx context.Context, session *models.Session) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, s := range h.services {
		if err := s.SessionRevoked(ctx, session); err != nil {
			return err
		}
	}
	for _, fn := range h.sessionRevoked {
		if err := fn(ctx, session); err != nil {
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

func (h *DefaultHookRegistry) OnAfterSignIn(fn SignInInterceptor) {
	if fn == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.afterSignIn = append(h.afterSignIn, fn)
}

func (h *DefaultHookRegistry) TriggerAfterSignIn(ctx context.Context, ev SignInEvent) (*SignInChallenge, error) {
	// Step 1: copy the interceptors so they can run without holding the lock
	h.mu.RLock()
	fns := append([]SignInInterceptor(nil), h.afterSignIn...)
	h.mu.RUnlock()
	// Step 2: run them in registration order; the first challenge replaces the response
	for _, fn := range fns {
		ch, err := fn(ctx, ev)
		if err != nil {
			return nil, err
		}
		if ch != nil {
			return ch, nil
		}
	}
	return nil, nil
}
