package serv_interfaces

import (
	"context"

	"github.com/better-go-auth/goauth/src/common/dtos"
	"github.com/better-go-auth/goauth/src/models"
)

type VerOpt struct {
	UserId string
}
type IVerificationService interface {
	SendVerification(ctx context.Context, identifier string, purpose models.VerificationPurpose, opt *VerOpt) (dtos.GResp[bool], error)
	VerifyCode(ctx context.Context, identifier string, purpose models.VerificationPurpose, value string) (dtos.GResp[models.Verification], error)
	DeleteByIdentifier(ctx context.Context, identifier string, purpose models.VerificationPurpose) error
}

type ISessionService interface {
	CreateSession(ctx context.Context, sessionId, role, userId string, opt *models.SessionOpt) (tkn *models.AuthTokens, eror error)
	DeleteSession(ctx context.Context, sessionId string) error
	DeleteAllUserSessions(ctx context.Context, userId string) error
	BlacklistSession(ctx context.Context, sessionId string) error
	// FindByRefreshToken returns the live session behind a refresh (session) token, or nil.
	FindByRefreshToken(ctx context.Context, refreshToken string) (*models.Session, error)
	// RefreshTokens slides the session, optionally rotates its token and signs a new access token.
	RefreshTokens(ctx context.Context, s *models.Session, role string) (*models.AuthTokens, error)
}

type IAuthServices interface {
	IVerificationService
	ISessionService
}

// AuthServiceImpl Add a concrete combiner type to account_interfaces/core.interface.go
type AuthServiceImpl struct {
	IVerificationService
	ISessionService
}
