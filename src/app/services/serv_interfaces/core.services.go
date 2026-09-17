package serv_interfaces

import (
	"context"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/birukbelay/gocmn/src/dtos"
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
