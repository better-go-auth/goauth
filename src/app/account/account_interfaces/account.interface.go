package account_interfaces

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
}

type ISessionService interface{
	CreateSession(ctx context.Context, sessionId, role, userId string, opt *models.SessionOpt) (tkn *models.AuthTokens, eror error)
}