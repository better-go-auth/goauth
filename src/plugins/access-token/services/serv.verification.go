package services

import (
	"context"
	"errors"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/common/dtos"
	"github.com/better-go-auth/goauth/src/common/logger"
	"github.com/better-go-auth/goauth/src/common/util"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins/access-token/services/interfaces"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
	"gorm.io/gorm"
)

type VerificationService struct {
	// VerificationCodeSender email.VerificationSender
	Repo   repo_interfaces.IVerificationRepo
	GormDB *gorm.DB
	Config config.EmailVerification
}

var _ interfaces.IVerificationService = (*VerificationService)(nil)



// NewVerificationService creates a VerificationService backed by any IVerificationRepo implementation.
func NewVerificationService(repo repo_interfaces.IVerificationRepo, config config.EmailVerification) *VerificationService {
	return &VerificationService{
		Repo: repo,
		// VerificationCodeSender: config.VerificationCodeSender,
		Config: config,
	}
}



func (vSvc *VerificationService) SendVerification(ctx context.Context, identifier string, purpose models.VerificationPurpose, opt *interfaces.VerOpt) (dtos.GResp[bool], error) {
	if vSvc.Config.GoAuth.CodeSender == nil {
		return dtos.InternalErrMS[bool]("no verification code sender configured"), errors.New("no verification code sender configured")
	}
	if vSvc.Repo == nil {
		return dtos.InternalErrMS[bool]("no storage"), errors.New("no storage configured")
	}
	verificationCode := ""
	if vSvc.Config.GoAuth.CodeGenerator != nil {
		verificationCode = vSvc.Config.GoAuth.CodeGenerator()
	} else {
		verificationCode = util.GenerateRandomString(6)
	}

	codeHash, err := authcrypto.HashPasswordBcrypt(verificationCode)
	if err != nil {
		return dtos.InternalErrMS[bool]("Hashing Error"), err
	}
	emailerr := vSvc.Config.GoAuth.CodeSender.SendVerificationCode(identifier, verificationCode)
	if emailerr != nil {
		return dtos.InternalErrMS[bool]("Queueing Email error"), emailerr
	}

	expiresIn := vSvc.Config.GoAuth.CodeExpiresIn
	if expiresIn <= 0 {
		expiresIn = 15 * time.Minute
	}

	var userID string
	if opt != nil {
		userID = opt.UserId
	}
	_, err = vSvc.Repo.UpsertVerificationValue(ctx, &models.Verification{
		Base:       models.Base{ID: models.NewID()},
		ExpiresAt:  time.Now().Add(expiresIn),
		Value:      codeHash,
		Identifier: purpose.Make(identifier),
		UserID:     userID,
	})
	if err != nil {
		logger.ErrorCtx(ctx, "error creating verification", err,nil)
		return dtos.InternalErrMS[bool]("creating Error"), err
	}
	return dtos.SuccessCreated(true, 1), nil

	// TODO: remove: use this as A fallback
	// if vSvc.GormDB != nil {
	// 	verificationResp, err := generic.DbUpsertOneListedFields[models.Verification](gormutil.GetDB(ctx, vSvc.GormDB), ctx, models.Verification{
	// 		ExpiresAt:  time.Now().Add(vSvc.Config.GoAuth.CodeExpiresIn),
	// 		Value:      codeHash,
	// 		Identifier: purpose.Make(identifier),
	// 		UserId:     opt.UserId,
	// 	}, []clause.Column{{Name: "identifier"}}, []string{"expires_at", "value"}, nil)
	// 	if err != nil {
	// 		logger.LogTrace("error crating verification", err)
	// 		return dtos.InternalErrMS[bool]("creating Error"), err
	// 	}
	// 	return dtos.SuccessCreated(true, verificationResp.RowsAffected), nil
	// }
}

// func (vSvc *VerificationService) VerifyCode(ctx context.Context, identifier string, purpose models.VerificationPurpose, code string) (dtos.GResp[models.Verification], error) {
// 	if vSvc.Repo == nil {
// 		return dtos.InternalErrMS[models.Verification]("no storage"), errors.New("no storage configured")
// 	}
// 	fullIdentifier := purpose.Make(identifier)
// 	v, err := vSvc.Repo.FindVerificationValue(ctx, fullIdentifier)
// 	if err != nil {
// 		return dtos.InternalErrMS[models.Verification]("Hashing Error"), err
// 	}
// 	if v.ExpiresAt.Before(time.Now()) {
// 		return dtos.InternalErrMS[models.Verification]("Hashing Error"), errors.New("code expired")
// 	}
// 	valid, _ := authcrypto.VerifyPassword(v.Value, code)
// 	if !valid {
// 		return dtos.InternalErrMS[models.Verification]("Hashing Error"), errors.New("invalid verification code")
// 	}
// 	return dtos.SuccessCreated(*v, 1), nil
// }

// func (vSvc *VerificationService) DeleteExpired(ctx context.Context) error {
// 	return vSvc.Repo.DeleteExpiredVerifications(ctx)
// }

// func (vSvc *VerificationService) DeleteByIdentifier(ctx context.Context, identifier string, purpose models.VerificationPurpose) error {
// 	fullIdentifier := purpose.Make(identifier)
// 	return vSvc.Repo.DeleteVerificationByIdentifier(ctx, fullIdentifier)
// }
