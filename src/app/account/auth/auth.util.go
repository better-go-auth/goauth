package auth

import (
	"context"
	"fmt"

	ICrypt "github.com/birukbelay/gocmn/src/crypto"
	"github.com/birukbelay/gocmn/src/generic"
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
