package serv_interfaces

// this is the legacy session and verification services
import (
	"context"
	"time"

	"github.com/better-go-auth/goauth/src/common/dtos"
	"github.com/better-go-auth/goauth/src/models"
	authdtos "github.com/better-go-auth/goauth/src/models/dtos"
)

type VerOpt struct {
	UserId string
}
type IVerificationService interface {
	SendVerification(ctx context.Context, identifier string, purpose models.VerificationPurpose, opt *VerOpt) (dtos.GResp[bool], error)
	VerifyCode(ctx context.Context, identifier string, purpose models.VerificationPurpose, value string) (dtos.GResp[models.Verification], error)
	DeleteByIdentifier(ctx context.Context, identifier string, purpose models.VerificationPurpose) error
}

type LegacySessionService interface {
	CreateSession(ctx context.Context, sessionId, role, userId string, opt *models.SessionOpt) (tkn *models.AuthTokens, eror error)
	DeleteSession(ctx context.Context, sessionId string) error
	DeleteAllUserSessions(ctx context.Context, userId string) error
	BlacklistSession(ctx context.Context, sessionId string) error
	// FindByRefreshToken returns the live session behind a refresh (session) token, or nil.
	FindByRefreshToken(ctx context.Context, refreshToken string) (*models.Session, error)
	// RefreshTokens slides the session, optionally rotates its token and signs a new access token.
	RefreshTokens(ctx context.Context, s *models.Session, role string) (*models.AuthTokens, error)
}

type ILegacyAuthServices interface {
	IVerificationService
	LegacySessionService
}

// LegacyAuthServiceImpl Add a concrete combiner type to account_interfaces/core.interface.go
type LegacyAuthServiceImpl struct {
	IVerificationService
	LegacySessionService
}

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
type ISessionService interface {
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
type ISessionManager = ISessionService

// INormalAuthServices combines normal Better-Auth services provided to plugins.
type INormalAuthServices interface {
	ISessionService
}

