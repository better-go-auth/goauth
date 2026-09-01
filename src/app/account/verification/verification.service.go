package verification

import (
	"context"
	"time"

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
	GormDB                 *gorm.DB
}

// TODO get the transaction from the context
func (aus Service) SendVerification(ctx context.Context, identifier, userId string, purpose models.VerificationPurpose) (dtos.GResp[bool], error) {
	//TODO make the mock and generation with a config
	// verificationCode := "000000"
	verificationCode := util.GenerateRandomString(6)

	codeHash, err := crypto.BcryptCreateHash(verificationCode)
	if err != nil {
		return dtos.InternalErrMS[bool]("Hashing Error"), err
	}
	emailerr := aus.VerificationCodeSender.SendVerificationCode(identifier, verificationCode)
	if emailerr != nil {
		return dtos.InternalErrMS[bool]("Queueing Email error"), emailerr
	}

	verificationResp, err := generic.DbUpsertOneListedFields[models.Verification](aus.GormDB, ctx, models.Verification{
		ExpiresAt:  time.Now().Add(time.Minute * 30), //todo make this in a config
		Value:      codeHash,
		Identifier: purpose.Make(identifier),
		UserId:     userId,
	}, []clause.Column{{Name: "identifier"}}, []string{"expires_at", "value"}, nil)
	if err != nil {
		logger.LogTrace("error crating verification", err)
		return dtos.InternalErrMS[bool]("creating Error"), err
	}
	return dtos.SuccessS(true, verificationResp.RowsAffected), nil
}

// VerifyCode TODO: add reason of error, like code expires
func (aus Service) VerifyCode(ctx context.Context, verifyInfo string, code string, verifyBy models.UpsertField) bool {
	filter := models.Verification{}
	if verifyBy == models.UpsertByEmail {
		filter.Email = verifyInfo
	} else {
		filter.UserId = verifyInfo
	}
	codeModel, err := generic.DbGetOne[models.Verification](aus.GormDB, ctx, filter, nil)
	if err != nil {
		return false
	}
	//if the expiration has passed, beofre now
	if codeModel.Body.ExpiresAt.Before(time.Now()) {
		return false
	}
	valid := crypto.BcryptPasswordsMatch(code, codeModel.Body.CodeHash)
	if !valid {
		return false
	}
	//5: invalidate the code by deleting it
	_, err = generic.DbDeleteByFilter[models.Verification](aus.GormDB, ctx, filter, nil)
	if err != nil {
		logger.LogError("Deleting user sessions errors", err.Error())
		// return dtos.InternalErrMS[bool]("Deleting verification code errors"), err
	}
	return true
}
