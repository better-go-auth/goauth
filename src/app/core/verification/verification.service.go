package verification

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/gormauth"
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/app/services/serv_interfaces"
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
	VerificationCodeSender email.VerificationSender
	Repo                   repo_interfaces.IVerificationRepo
	GormDB                 *gorm.DB
	Config                 config.EmailVerification
}

// NewVerificationService creates a VerificationService backed by a *gorm.DB (backward compatibility).
func NewVerificationService(dg *gorm.DB, config config.EmailVerification) serv_interfaces.IVerificationService {
	var repo repo_interfaces.IVerificationRepo
	if dg != nil {
		repo = gormauth.NewVerificationRepo(dg)
	}
	return &Service{
		GormDB:                 dg,
		Repo:                   repo,
		VerificationCodeSender: config.VerificationCodeSender,
		Config:                 config,
	}
}

// NewVerificationServiceWithRepo creates a VerificationService backed by any IVerificationRepo implementation.
func NewVerificationServiceWithRepo(repo repo_interfaces.IVerificationRepo, config config.EmailVerification) serv_interfaces.IVerificationService {
	return &Service{
		Repo:                   repo,
		VerificationCodeSender: config.VerificationCodeSender,
		Config:                 config,
	}
}

func (vSvc Service) SendVerification(ctx context.Context, identifier string, purpose models.VerificationPurpose, opt *serv_interfaces.VerOpt) (dtos.GResp[bool], error) {
	verificationCode := ""
	if vSvc.Config.CodeGenerator != nil {
		verificationCode = vSvc.Config.CodeGenerator()
	} else {
		verificationCode = util.GenerateRandomString(6)
	}

	codeHash, err := crypto.BcryptCreateHash(verificationCode)
	if err != nil {
		return dtos.InternalErrMS[bool]("Hashing Error"), err
	}
	if vSvc.VerificationCodeSender != nil {
		emailerr := vSvc.VerificationCodeSender.SendVerificationCode(identifier, verificationCode)
		if emailerr != nil {
			return dtos.InternalErrMS[bool]("Queueing Email error"), emailerr
		}
	}

	if vSvc.Repo != nil {
		var userID string
		if opt != nil {
			userID = opt.UserId
		}
		_, err := vSvc.Repo.UpsertVerification(ctx, &models.Verification{
			ExpiresAt:  time.Now().Add(vSvc.Config.ExpiresIn),
			Value:      codeHash,
			Identifier: purpose.Make(identifier),
			UserId:     userID,
		})
		if err != nil {
			logger.LogTrace("error creating verification", err)
			return dtos.InternalErrMS[bool]("creating Error"), err
		}
		return dtos.SuccessCreated(true, 1), nil
	}
	// TODO: remove: use this as A fallback
	if vSvc.GormDB != nil {
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
		return dtos.SuccessCreated(true, verificationResp.RowsAffected), nil
	}

	return dtos.InternalErrMS[bool]("no verification storage available"), errors.New("no verification storage configured")
}

func (vSvc Service) VerifyCode(ctx context.Context, identifier string, purpose models.VerificationPurpose, code string) (dtos.GResp[models.Verification], error) {
	if vSvc.Repo != nil {
		v, err := vSvc.Repo.GetVerification(ctx, identifier, purpose)
		if err != nil {
			return dtos.InternalErrMS[models.Verification]("Hashing Error"), err
		}
		if v.ExpiresAt.Before(time.Now()) {
			return dtos.InternalErrMS[models.Verification]("Hashing Error"), errors.New("code expired")
		}
		valid := crypto.BcryptPasswordsMatch(code, v.Value)
		if !valid {
			return dtos.InternalErrMS[models.Verification]("Hashing Error"), errors.New("invalid verification code")
		}
		return dtos.SuccessCreated(*v, 1), nil
	}

	if vSvc.GormDB != nil {
		filter := models.Verification{Identifier: purpose.Make(identifier)}
		verificationModel, err := generic.DbGetOne[models.Verification](vSvc.GormDB, ctx, filter, nil)
		if err != nil {
			return dtos.InternalErrMS[models.Verification]("Hashing Error"), err
		}
		if verificationModel.Body.ExpiresAt.Before(time.Now()) {
			return dtos.InternalErrMS[models.Verification]("Hashing Error"), errors.New("hashing error")
		}
		valid := crypto.BcryptPasswordsMatch(code, verificationModel.Body.Value)
		if !valid {
			return dtos.InternalErrMS[models.Verification]("Hashing Error"), errors.New("invalid verification code")
		}
		return dtos.SuccessCreated(verificationModel.Body, verificationModel.RowsAffected), nil
	}

	return dtos.InternalErrMS[models.Verification]("no storage"), errors.New("no storage configured")
}

func (vSvc Service) DeleteExpired(ctx context.Context) error {
	if vSvc.Repo != nil {
		return vSvc.Repo.DeleteExpired(ctx)
	}
	if vSvc.GormDB != nil {
		if err := gormutil.GetDB(ctx, vSvc.GormDB).Where("expires_at < NOW()").Delete(&models.Verification{}).Error; err != nil {
			return fmt.Errorf("gorm/verification: delete expired: %w", err)
		}
	}
	return nil
}

func (vSvc Service) DeleteByIdentifier(ctx context.Context, identifier string, purpose models.VerificationPurpose) error {
	if vSvc.Repo != nil {
		return vSvc.Repo.DeleteVerification(ctx, identifier, purpose)
	}
	if vSvc.GormDB != nil {
		filter := models.Verification{Identifier: purpose.Make(identifier)}
		_, err := generic.DbDeleteByFilter[models.Verification](gormutil.GetDB(ctx, vSvc.GormDB), ctx, filter, nil)
		if err != nil {
			logger.LogError("Deleting user sessions errors", err.Error())
			return fmt.Errorf("gorm/verification: delete: %w", err)
		}
	}
	return nil
}
