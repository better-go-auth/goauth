package account

import (
	"context"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/birukbelay/gocmn/src/dtos"
)

type VerOpt struct {
	UserId string
}
type VerificationService interface {
	SendVerification(ctx context.Context, identifier string, purpose models.VerificationPurpose, opt *VerOpt) (dtos.GResp[bool], error)
	VerifyCode(ctx context.Context, identifier string, purpose models.VerificationPurpose, value string) (bool, error)
}
