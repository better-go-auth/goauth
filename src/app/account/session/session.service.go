package session

import (
	"context"
	"fmt"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/providers"
	"github.com/birukbelay/gocmn/src/crypto"
	"github.com/birukbelay/gocmn/src/generic"
	"gorm.io/gorm/clause"
)

type Service struct {
	ProvServ *providers.IProviderS
}

func NewService(genServ *providers.IProviderS) *Service {
	return &Service{
		ProvServ: genServ,
	}
}

type SessionOpt struct {
	ClearSession bool
	ActiveOrgID  *string
	OrgRoleID    *string
	DeviceToken  string
}

func (aus Service) GenerateTokens(user *crypto.CustomClaims) (*models.AuthTokens, error) {
	claims := &crypto.CustomClaims{
		Role:      user.Role,
		UserId:    user.UserId,
		CompanyId: user.CompanyId,
		SessionId: user.SessionId,
	}
	accessToken, err := crypto.SignAccessToken(aus.ProvServ.EnvConf.JwtVar.AccessSecret, aus.ProvServ.EnvConf.JwtVar.AccessExpireMin, claims)
	if err != nil {
		return nil, err
	}
	refreshToken, err := crypto.SignRefreshToken(aus.ProvServ.EnvConf.JwtVar.RefreshSecret, aus.ProvServ.EnvConf.JwtVar.RefreshExpireMin, claims)
	if err != nil {
		return nil, err
	}

	return &models.AuthTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil

}

func (aus Service) CreateSession(ctx context.Context, sessionId, role, userId string, opt *SessionOpt) (tkn *models.AuthTokens, eror error) {
	//	3. Generate auth Token of password
	claims := crypto.CustomClaims{Role: role, UserId: userId, SessionId: sessionId}
	if opt != nil {
		claims.CompanyId = *opt.ActiveOrgID
	}
	tokens, err := aus.GenerateTokens(&claims)
	if err != nil {
		return nil, err
	}
	//4. hash the refresh token
	refreshHash, err := crypto.ArgonCreateHash(tokens.RefreshToken)
	if err != nil {
		return nil, err
	}
	tx := aus.ProvServ.GormConn.Begin()
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
		_, err = generic.DbDeleteByFilter[models.Session](aus.ProvServ.GormConn, ctx, models.Session{UserID: userId}, &generic.Opt{Debug: false})
		if err != nil {
			// return nil, err
		}
	}

	session := models.Session{
		UserID:        userId,
		HashedRefresh: refreshHash,
		SessionId:     sessionId,
		Role:          role,
	}
	if opt != nil {
		session.ActiveOrgID = opt.ActiveOrgID
		session.OrgRoleID = opt.OrgRoleID
		session.DeviceToken = opt.DeviceToken
	}

	//4.Create a session or update previous's hashed_refresh
	_, err = generic.DbUpsertOneListedFields[models.Session](tx, ctx, session,
		[]clause.Column{{Name: "session_id"}},
		[]string{"hashed_refresh", "device_token", "active_org_id"}, &generic.Opt{Debug: false})
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
