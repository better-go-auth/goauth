package interfaces

// this is the legacy session and verification services
import (
	"context"

	svcint "github.com/better-go-auth/goauth/src/app/services/interfaces"
	"github.com/better-go-auth/goauth/src/common/dtos"
	"github.com/better-go-auth/goauth/src/models"
	mdtos "github.com/better-go-auth/goauth/src/models/dtos"
	accesstokendtos "github.com/better-go-auth/goauth/src/plugins/access-token/dtos"
)

type VerOpt struct {
	UserId string
}
type IVerificationService interface {
	SendVerification(ctx context.Context, identifier string, purpose models.VerificationPurpose, opt *VerOpt) (dtos.GResp[bool], error)
	// VerifyCode(ctx context.Context, identifier string, purpose models.VerificationPurpose, value string) (dtos.GResp[models.Verification], error)
	// DeleteByIdentifier(ctx context.Context, identifier string, purpose models.VerificationPurpose) error
}

type LegacySessionService interface {
	// CreateSession(ctx context.Context, sessionId, role, userId string, opt *models.SessionOpt) (tkn *models.AuthTokens, eror error)
	DeleteSession(ctx context.Context, sessionId string) error
	// DeleteAllUserSessions(ctx context.Context, userId string) error
	BlacklistSession(ctx context.Context, sessionId string) error
	// GetBySID resolves a session by its id via the plugin-owned sid: -> token index.
	GetBySID(ctx context.Context, sid string) (*mdtos.SessionWithUser, error)
	// FindByRefreshToken returns the live session behind a refresh (session) token, or nil.
	FindByRefreshToken(ctx context.Context, refreshToken string) (*models.Session, error)
	// RefreshTokens slides the session, optionally rotates its token and signs a new access token.
	RefreshTokens(ctx context.Context, s *models.Session, role string) (*models.AuthTokens, error)
}

// IAccessTokenAuthService defines authentication endpoints for access-token / JWT flow.
type IAccessTokenAuthService interface {
	RegisterWithEmail(ctx context.Context, input models.RegisterClientInput) (*svcint.SignUpResult, error)
	// VerifyRegisteredUser(ctx context.Context, input accesstokendtos.VerificationInput) (dtos.GResp[models.User], error)
	Login(ctx context.Context, input accesstokendtos.LoginData) (dtos.GResp[accesstokendtos.TokenResponse], error)
	ResetToken(ctx context.Context, token string) (dtos.GResp[accesstokendtos.TokenResponse], error)
	Logout(ctx context.Context, token string) (dtos.GResp[bool], error)
	// ForgotPwd(ctx context.Context, input accesstokendtos.VerifyReqInput) (dtos.GResp[bool], error)
	// ResetPwd(ctx context.Context, input accesstokendtos.PwdResetInput) (dtos.GResp[bool], error)
}

// IAccessTokenSessionService manages JWT access token + refresh token sessions.
type IAccessTokenSessionService interface {
	LegacySessionService
}
