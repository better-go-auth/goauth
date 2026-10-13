package interfaces

import (
	"context"
	"time"

	"github.com/better-go-auth/goauth/src/models"
	authdtos "github.com/better-go-auth/goauth/src/models/dtos"
)

// ─── Normal Better-Auth Service Interfaces ─────────────────────────────────────

// SessionMeta is request metadata stored on new sessions.
type SessionMeta struct {
	IPAddress string
	UserAgent string
}

// SessionCreateOptions customises a new session.
type SessionCreateOptions struct {
	// DontRemember creates a 1-day session that is never refreshed (rememberMe=false).
	DontRemember           bool
	ExpiresIn              time.Duration
	ImpersonatedBy         *string
	ActiveOrganizationID   *string
	ID                     string
	ActiveOrganizationRole *string
	DeviceToken            string
}

// ISessionService defines normal Better-Auth session operations (implemented by session.Manager).
type ISessionManager interface {
	Create(ctx context.Context, user *models.User, meta SessionMeta, opt SessionCreateOptions) (*authdtos.SessionWithUser, error)
	Get(ctx context.Context, tok string) (*authdtos.SessionWithUser, error)
	Update(ctx context.Context, swu *authdtos.SessionWithUser, data map[string]any) (*authdtos.SessionWithUser, error)
	Delete(ctx context.Context, tok string) error
	DeleteUserSessions(ctx context.Context, userID string) error
	Refresh(ctx context.Context, swu *authdtos.SessionWithUser) (*authdtos.SessionWithUser, error)
	RotateToken(ctx context.Context, swu *authdtos.SessionWithUser) (*authdtos.SessionWithUser, error)
	ShouldRefresh(sw *authdtos.SessionWithUser, dontRemember bool) bool
}

// ISessionManager is an alias for ISessionService.
// type ISessionManager = ISessionService

// INormalAuthServices combines normal Better-Auth services provided to plugins.
// type INormalAuthServices interface {
// 	ISessionService
// }
