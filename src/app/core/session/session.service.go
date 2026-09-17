package session

import (
	"context"
	"fmt"
	"time"

	"github.com/better-go-auth/goauth/src/app/services/serv_interfaces"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/providers"
	"github.com/birukbelay/gocmn/src/crypto"
	"github.com/birukbelay/gocmn/src/dtos"
	"github.com/birukbelay/gocmn/src/generic"
	"github.com/birukbelay/gocmn/src/provider/db"
	"gorm.io/gorm/clause"
)

type Service struct {
	ProvServ *providers.IProviderS
	sConf    config.SessionConfig
	sStore   db.KeyValServ
}

func NewService(conf config.SessionConfig, genServ *providers.IProviderS) *Service {
	return &Service{
		ProvServ: genServ,
		sConf:    conf,
		sStore:   genServ.SecondaryStorage,
	}
}

var _ serv_interfaces.ISessionService = (*Service)(nil)

func (aus Service) GenerateTokens(user *crypto.CustomClaims) (*models.AuthTokens, error) {
	claims := &crypto.CustomClaims{
		Role:      user.Role,
		UserId:    user.UserId,
		CompanyId: user.CompanyId,
		SessionId: user.SessionId,
	}
	accessToken, err := crypto.SignAccessToken(aus.sConf.JwtVar.AccessSecret, aus.sConf.JwtVar.AccessExpireMin, claims)
	if err != nil {
		return nil, err
	}
	refreshToken, err := crypto.SignRefreshToken(aus.sConf.JwtVar.RefreshSecret, aus.sConf.JwtVar.RefreshExpireMin, claims)
	if err != nil {
		return nil, err
	}

	return &models.AuthTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (aus Service) CreateSession(ctx context.Context, sessionId, role, userId string, opt *models.SessionOpt) (tkn *models.AuthTokens, eror error) {
	//	3. Generate auth Token of password
	claims := crypto.CustomClaims{Role: role, UserId: userId, SessionId: sessionId}
	if opt != nil && opt.ActiveOrgID != nil {
		claims.CompanyId = *opt.ActiveOrgID
	}
	tokens, err := aus.GenerateTokens(&claims)
	if err != nil {
		return nil, err
	}
	// 4. hash the refresh token
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

	expiresIn := time.Duration(aus.sConf.JwtVar.RefreshExpireMin) * time.Minute
	if expiresIn <= 0 {
		expiresIn = 7 * 24 * time.Hour
	}

	session := models.Session{
		UserID:      userId,
		HashedToken: refreshHash,
		SessionId:   sessionId,
		Role:        role,
		ExpiresAt:   time.Now().UTC().Add(expiresIn),
	}
	if opt != nil {
		session.ActiveOrgID = opt.ActiveOrgID
		session.OrgRoleID = opt.OrgRoleID
		session.DeviceToken = opt.DeviceToken
	}

	// 4.Create a session or update previous's hashed_token
	_, err = generic.DbUpsertOneListedFields[models.Session](tx, ctx, session,
		[]clause.Column{{Name: "session_id"}},
		[]string{"hashed_token", "device_token", "active_org_id", "expires_at"}, &generic.Opt{Debug: false})
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

func (aus Service) BlacklistSession(ctx context.Context, sessionId string) error {
	if aus.sStore == nil {
		return nil
	}
	key := fmt.Sprintf("blacklist:%s", sessionId)
	ttl := time.Hour
	if aus.sConf.JwtVar.RefreshExpireMin > 0 {
		ttl = time.Duration(aus.sConf.JwtVar.RefreshExpireMin) * time.Minute
	}
	return aus.sStore.Set(ctx, key, "blacklisted", ttl)
}

func (aus Service) DeleteSession(ctx context.Context, sessionId string) error {
	_, err := generic.DbDeleteByFilter[models.Session](gormutil.GetDB(ctx, aus.ProvServ.GormConn), ctx, models.SessionFilter{SessionId: sessionId}, nil)
	if err != nil {
		return err
	}
	return aus.BlacklistSession(ctx, sessionId)
}

func (aus Service) DeleteAllUserSessions(ctx context.Context, userId string) error {
	sessions, err := generic.DbFetchManyWithOffset[models.Session](gormutil.GetDB(ctx, aus.ProvServ.GormConn), ctx, models.SessionFilter{UserId: userId}, dtos.PaginationInput{Limit: 10000}, nil)
	if err == nil {
		for _, s := range sessions.Body {
			_ = aus.BlacklistSession(ctx, s.SessionId)
		}
	}
	_, err = generic.DbDeleteByFilter[models.Session](gormutil.GetDB(ctx, aus.ProvServ.GormConn), ctx, models.SessionFilter{UserId: userId}, nil)
	return err
}
