package profile

import (
	"context"
	"time"

	"github.com/better-go-auth/goauth/src/models"
	ICrypt "github.com/birukbelay/gocmn/src/crypto"
	"github.com/birukbelay/gocmn/src/dtos"
	"github.com/birukbelay/gocmn/src/generic"
	cmn "github.com/birukbelay/gocmn/src/logger"
	"github.com/birukbelay/gocmn/src/util"
)

func (aus Service[T]) UTIL_SendVerification(ctx context.Context, email, userId string, purpose models.CodePurpose) (dtos.GResp[bool], error) {
	//TODO genereate code here
	verificationCode := "000000"

	codeHash, err := ICrypt.BcryptCreateHash(verificationCode)
	if err != nil {
		return dtos.InternalErrMS[bool]("Hashing Error"), err
	}
	emailerr := aus.ProvServ.VerificationCodeSender.SendVerificationCode(email, verificationCode)
	if emailerr != nil {
		return dtos.InternalErrMS[bool]("Sending Email error"), emailerr
	}
	_, _ = generic.DbDeleteByFilter[models.VerificationCode](aus.ProvServ.GormConn, ctx, models.VerificationCode{UserId: userId}, nil)
	verificationResp, err := generic.DbCreateOne[models.VerificationCode](aus.ProvServ.GormConn, ctx, models.VerificationCode{
		ExpiresAt: util.Ptr(time.Now().Add(time.Minute * 3)),
		CodeHash:  codeHash,
		Purpose:   purpose,
		UserId:    userId,
		Email:     email,
	}, nil)
	if err != nil {
		cmn.LogTrace("error crating", err)
		return dtos.InternalErrMS[bool]("creating Error"), err
	}
	return dtos.SuccessS(true, verificationResp.RowsAffected), nil
}
func (aus Service[T]) VerifyCode(ctx context.Context, userId string, code string) (bool, string) {
	codeModel, err := generic.DbGetOne[models.VerificationCode](aus.ProvServ.GormConn, ctx, models.VerificationCode{UserId: userId}, nil)
	if err != nil {
		return false, ""
	}
	if codeModel.Body.ExpiresAt.Before(time.Now()) {
		return false, ""
	}
	valid := ICrypt.BcryptPasswordsMatch(code, codeModel.Body.CodeHash)
	if !valid {
		return false, ""
	}
	return true, codeModel.Body.Email
}
