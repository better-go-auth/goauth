package auth

import (
	"context"
	"fmt"
	"time"

	ICrypt "github.com/birukbelay/gocmn/src/crypto"
	"github.com/birukbelay/gocmn/src/dtos"
	"github.com/birukbelay/gocmn/src/generic"
	"github.com/birukbelay/gocmn/src/logger"
	"github.com/birukbelay/gocmn/src/util"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/better-go-auth/goauth/src/models"
)

func (aus Service[T]) GenerateTokens(user *ICrypt.CustomClaims) (*AuthTokens, error) {
	claims := &ICrypt.CustomClaims{
		Role:      user.Role,
		UserId:    user.UserId,
		CompanyId: user.CompanyId,
		SessionId: user.SessionId,
	}
	accessToken, err := ICrypt.SignAccessToken(aus.Config.AccessSecret, aus.Config.AccessExpireMin, claims)
	if err != nil {
		return nil, err
	}
	refreshToken, err := ICrypt.SignRefreshToken(aus.Config.RefreshSecret, aus.Config.RefreshExpireMin, claims)
	if err != nil {
		return nil, err
	}

	return &AuthTokens{
		accessToken, refreshToken,
	}, nil

}

// VerifyCode TODO: add reason of error, like code expires
func (aus Service[T]) VerifyCode(tx *gorm.DB, ctx context.Context, verifyInfo string, code string, verifyBy models.UpsertField) bool {
	filter := models.VerificationCode{}
	if verifyBy == models.UpsertByEmail {
		filter.Email = verifyInfo
	} else {
		filter.UserId = verifyInfo
	}
	codeModel, err := generic.DbGetOne[models.VerificationCode](tx, ctx, filter, nil)
	if err != nil {
		return false
	}
	//if the expiration has passed, beofre now
	if codeModel.Body.ExpiresAt.Before(time.Now()) {
		return false
	}
	valid := ICrypt.BcryptPasswordsMatch(code, codeModel.Body.CodeHash)
	if !valid {
		return false
	}
	//5: invalidate the code by deleting it
	_, err = generic.DbDeleteByFilter[models.VerificationCode](tx, ctx, filter, nil)
	if err != nil {
		logger.LogError("Deleting user sessions errors", err.Error())
		// return dtos.InternalErrMS[bool]("Deleting verification code errors"), err
	}
	return true
}

type SessionOpt struct {
	ClearSession  bool
	CompanyRoleID *string
}

func (aus Service[T]) UTIL_MakeSession(ctx context.Context, sessionId, role, userId, companyId, deviceToken string, opt *SessionOpt) (tkn *AuthTokens, eror error) {
	//	3. Generate auth Token of password
	tokens, err := aus.GenerateTokens(&ICrypt.CustomClaims{Role: role, UserId: userId, CompanyId: companyId, SessionId: sessionId})
	if err != nil {
		return nil, err
	}
	//4. hash the refresh token
	refreshHash, err := ICrypt.ArgonCreateHash(tokens.RefreshToken)
	if err != nil {
		return nil, err
	}
	tx := aus.Provider.GormConn.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			eror = fmt.Errorf("panic occurred: %v", r)
			tkn = nil
		}
	}()
	if err := tx.Error; err != nil {
		return nil, err
	}
	if opt != nil && opt.ClearSession {
		_, err = generic.DbDeleteByFilter[models.Session](aus.Provider.GormConn, ctx, models.Session{UserId: userId}, &generic.Opt{Debug: false})
		if err != nil {
			// return nil, err
		}
	}
	var companyRoleID *string
	if opt != nil {
		companyRoleID = opt.CompanyRoleID
	}
	session := models.Session{
		UserId:        userId,
		HashedRefresh: refreshHash,
		SessionId:     sessionId,
		CompanyID:     &companyId,
		CompanyRoleID: companyRoleID,
	}
	if deviceToken != "" {
		session.DeviceToken = deviceToken

	}

	//4.Create a session or update previous's hashed_refresh
	_, err = generic.DbUpsertOneListedFields[models.Session](tx, ctx, session, []clause.Column{{Name: "session_id"}}, []string{"hashed_refresh", "device_token", "company_id", "company_role_id"}, &generic.Opt{Debug: false})
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	commit := tx.Commit()
	if commit.Error != nil {
		return nil, commit.Error
	}
	return tokens, nil
}

// func (aus Service[T]) DestroySessions(ctx context.Context, email, userId string) (dtos.GResp[bool], error) {

// }

func (aus Service[T]) UTIL_SendEmailVerification(tx *gorm.DB, ctx context.Context, email, userId string, upsertField models.UpsertField, purpose models.CodePurpose) (dtos.GResp[bool], error) {
	//TODO genereate code here
	// verificationCode := "000000"
	verificationCode := util.GenerateRandomString(6)

	codeHash, err := ICrypt.BcryptCreateHash(verificationCode)
	if err != nil {
		return dtos.InternalErrMS[bool]("Hashing Error"), err
	}
	//try to queue
	// emailerr := tasks.EnqueueVerificationEmail(ctx, aus.Provider.QueueClient, email, verificationCode)
	// if emailerr != nil {
	//try to send directly
	emailerr := aus.Provider.VerificationCodeSender.SendVerificationCode(email, verificationCode)
	if emailerr != nil {
		return dtos.InternalErrMS[bool]("Queueing Email error"), emailerr
	}
	// }

	//TODO: we need to specify which field to upsert, for signup it is email, but for pwd reset it is userId

	verificationResp, err := generic.DbUpsertOneListedFields[models.VerificationCode](tx, ctx, models.VerificationCode{
		ExpiresAt:   util.Ptr(time.Now().Add(time.Minute * 30)),
		CodeHash:    codeHash,
		Purpose:     purpose,
		UserId:      userId,
		Email:       email, //use this for both phone or email
		UpdertField: upsertField,
	}, []clause.Column{{Name: upsertField.S()}}, []string{"expires_at", "code_hash", "purpose", "email", "updert_field"}, nil)
	if err != nil {
		logger.LogTrace("error crating", err)
		return dtos.InternalErrMS[bool]("creating Error"), err
	}
	return dtos.SuccessS(true, verificationResp.RowsAffected), nil
}

// //====================.  Currently unused functions

// func (aus Service[T]) UTIL_SendVerification(ctx context.Context, email, userId string, purpose models.CodePurpose) (dtos.GResp[bool], error) {
// 	//TODO genereate code here
// 	verificationCode := "000000"

// 	codeHash, err := ICrypt.BcryptCreateHash(verificationCode)
// 	if err != nil {
// 		return dtos.InternalErrMS[bool]("Hashing Error"), err
// 	}
// 	// emailerr := aus.Provider.VerificationCodeSender.SendVerificationCode(email, verificationCode)
// 	// if emailerr != nil {
// 	// 	return dtos.InternalErrMS[bool]("Sending Email error"), emailerr
// 	// }
// 	verificationResp, err := generic.DbUpsertOneAllFields[models.VerificationCode](aus.Provider.GormConn, ctx, models.VerificationCode{
// 		ExpiresAt: util.Ptr(time.Now().Add(time.Minute * 30)),
// 		CodeHash:  codeHash,
// 		Purpose:   purpose,
// 		UserId:    userId,
// 		Email:     email,
// 	}, []clause.Column{{Name: "email"}}, &generic.Opt{Debug: false})
// 	if err != nil {
// 		logger.LogTrace("error crating", err)
// 		return dtos.InternalErrMS[bool]("creating Error"), err
// 	}
// 	return dtos.SuccessS(true, verificationResp.RowsAffected), nil
// }
