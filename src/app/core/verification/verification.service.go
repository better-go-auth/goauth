package verification

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/better-go-auth/goauth/src/app/core/core_interfaces"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/birukbelay/gocmn/src/crypto"
	"github.com/birukbelay/gocmn/src/dtos"
	"github.com/birukbelay/gocmn/src/generic"
	"github.com/birukbelay/gocmn/src/logger"
	"github.com/birukbelay/gocmn/src/provider/email"
	"github.com/birukbelay/gocmn/src/util"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Service struct {
	VerificationCodeSender email.VerificationSender //put this also on the cofig
	GormDB                 *gorm.DB
	Config                 config.EmailVerification
}

func NewVerificationService(dg *gorm.DB, config config.EmailVerification) core_interfaces.IVerificationService {
	return &Service{
		GormDB:                 dg,
		VerificationCodeSender: config.VerificationCodeSender,
		Config:                 config,
	}
}

// TODO get the transaction from the context
func (vSvc Service) SendVerification(ctx context.Context, identifier string, purpose models.VerificationPurpose, opt *core_interfaces.VerOpt) (dtos.GResp[bool], error) {
	//TODO make the mock and generation with a config
	// verificationCode := "000000"
	verificationCode := util.GenerateRandomString(6)

	codeHash, err := crypto.BcryptCreateHash(verificationCode)
	if err != nil {
		return dtos.InternalErrMS[bool]("Hashing Error"), err
	}
	emailerr := vSvc.VerificationCodeSender.SendVerificationCode(identifier, verificationCode)
	if emailerr != nil {
		return dtos.InternalErrMS[bool]("Queueing Email error"), emailerr
	}

	verificationResp, err := generic.DbUpsertOneListedFields[models.Verification](gormutil.GetDB(ctx, vSvc.GormDB), ctx, models.Verification{
		ExpiresAt:  time.Now().Add(vSvc.Config.ExpiresIn),
		Value:      codeHash,
		Identifier: purpose.Make(identifier),
		UserId:     opt.UserId,
	}, []clause.Column{{Name: "identifier"}}, []string{"expires_at", "value"}, nil)
	if err != nil {
		logger.LogTrace("error crating verification", err)
		return dtos.InternalErrMS[bool]("creating Error"), err
	}
	return dtos.SuccessS(true, verificationResp.RowsAffected), nil
}

// VerifyCode TODO: add reason of error, like code expires
func (vSvc Service) VerifyCode(ctx context.Context, identifier string, purpose models.VerificationPurpose, code string) (dtos.GResp[models.Verification], error) {
	filter := models.Verification{Identifier: purpose.Make(identifier)}
	verificationModel, err := generic.DbGetOne[models.Verification](vSvc.GormDB, ctx, filter, nil)
	if err != nil {
		return dtos.InternalErrMS[models.Verification]("Hashing Error"), err
	}
	//if the expiration has passed, beofre now
	if verificationModel.Body.ExpiresAt.Before(time.Now()) {
		return dtos.InternalErrMS[models.Verification]("Hashing Error"), errors.New("hashing error")
	}
	valid := crypto.BcryptPasswordsMatch(code, verificationModel.Body.Value)
	if !valid {
		return dtos.InternalErrMS[models.Verification]("Hashing Error"), err
	}
	//5: invalidate the code by deleting it
	// delResp, err := generic.DbDeleteByFilter[models.Verification](gormutil.GetDB(ctx, vSvc.GormDB), ctx, filter, nil)
	// if err != nil {
	// 	logger.LogError("Deleting user sessions errors", err.Error())
	// 	// return dtos.InternalErrMS[bool]("Deleting verification code errors"), err
	// }
	return dtos.SuccessS(verificationModel.Body, verificationModel.RowsAffected), nil
}

func (vSvc Service) DeleteExpired(ctx context.Context) error {
	if err := gormutil.GetDB(ctx, vSvc.GormDB).Where("expires_at < NOW()").Delete(&models.Verification{}).Error; err != nil {
		return fmt.Errorf("gorm/verification: delete expired: %w", err)
	}
	return nil
}

func (vSvc Service) DeleteByIdentifier(ctx context.Context, identifier string, purpose models.VerificationPurpose) error {
	filter := models.Verification{Identifier: purpose.Make(identifier)}
	_, err := generic.DbDeleteByFilter[models.Verification](gormutil.GetDB(ctx, vSvc.GormDB), ctx, filter, nil)
	if err != nil {
		logger.LogError("Deleting user sessions errors", err.Error())
		return fmt.Errorf("gorm/verification: delete expired: %w", err)
	}
	return nil
}
