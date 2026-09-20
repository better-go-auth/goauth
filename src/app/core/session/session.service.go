package session

import (
	"context"
	"fmt"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/app/services/serv_interfaces"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/providers/hasher"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
	"github.com/better-go-auth/goauth/src/providers/token"
	jwttoken "github.com/better-go-auth/goauth/src/providers/token/jwt-token"
)

type Service struct {
	SessionRepo repo_interfaces.ISessionRepo
	// ProvServ    *providers.IProviderS
	sConf  config.SessionConfig
	sStore sec_storage.SecondaryStorage
	Hooks  plugins.HookRegistry
}

func NewServiceWithRepo(conf config.SessionConfig, repo repo_interfaces.ISessionRepo, sStore sec_storage.SecondaryStorage, hooks ...plugins.HookRegistry) *Service {
	var h plugins.HookRegistry
	if len(hooks) > 0 {
		h = hooks[0]
	}
	return &Service{
		SessionRepo: repo,
		sConf:       conf,
		sStore:      sStore,
		Hooks:       h,
	}
}

var _ serv_interfaces.ISessionService = (*Service)(nil)

func (aus Service) GenerateTokens(user *token.CustomClaims) (*models.AuthTokens, error) {
	claims := &token.CustomClaims{
		Role:        user.Role,
		UserID:      user.UserID,
		ActiveOrgId: user.ActiveOrgId,
		// CompanyId: user.CompanyId,
		ActiveOrgRole: user.ActiveOrgRole,
		SessionID:     user.SessionID,
	}
	accessToken, err := jwttoken.SignWithExpiry(aus.sConf.JwtVar.AccessSecret, claims, time.Duration(aus.sConf.JwtVar.AccessExpireMin)*time.Minute)
	if err != nil {
		return nil, err
	}
	refreshToken, err := jwttoken.SignWithExpiry(aus.sConf.JwtVar.RefreshSecret, claims, time.Duration(aus.sConf.JwtVar.RefreshExpireMin)*time.Minute)
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
	claims := token.CustomClaims{Role: role, UserID: userId, SessionID: sessionId}
	if opt != nil && opt.ActiveOrgID != nil {
		claims.ActiveOrgId = *opt.ActiveOrgID
		// depricated: used for backward compatability
		// claims.CompanyId = *opt.ActiveOrgID
	}
	if opt != nil && opt.OrgRole != nil {
		claims.ActiveOrgRole = *opt.OrgRole
	}
	tokens, err := aus.GenerateTokens(&claims)
	if err != nil {
		return nil, err
	}
	// 4. hash the refresh token
	refreshHash, err := hasher.ArgonCreateHash(tokens.RefreshToken)
	if err != nil {
		return nil, err
	}
	if opt != nil && opt.ClearSession {
		// TODO: make sure the repo
		if aus.SessionRepo != nil {
			_ = aus.SessionRepo.DeleteSessionsByUserID(ctx, userId)
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

	if aus.Hooks != nil {
		_ = aus.Hooks.TriggerBeforeSessionCreate(ctx, &session, &claims)
	}

	if aus.SessionRepo != nil {
		_, err = aus.SessionRepo.UpsertSession(ctx, &session)
		if err != nil {
			return nil, err
		}
		return tokens, nil
	}

	// if aus.ProvServ != nil && aus.ProvServ.GormConn != nil {
	// 	tx := aus.ProvServ.GormConn.Begin()
	// 	defer func() {
	// 		if r := recover(); r != nil {
	// 			tx.Rollback()
	// 			eror = fmt.Errorf("panic occurred: %v", r)
	// 			tkn = nil
	// 		}
	// 	}()
	// 	if err := tx.Error; err != nil {
	// 		return nil, err
	// 	}

	// 	// 4.Create a session or update previous's hashed_token
	// 	_, err = generic.DbUpsertOneListedFields[models.Session](tx, ctx, session,
	// 		[]clause.Column{{Name: "session_id"}},
	// 		[]string{"hashed_token", "device_token", "active_org_id", "expires_at"}, &generic.Opt{Debug: false})
	// 	if err != nil {
	// 		tx.Rollback()
	// 		return nil, err
	// 	}
	// 	commit := tx.Commit()
	// 	if commit.Error != nil {
	// 		return nil, commit.Error
	// 	}
	// 	return tokens, nil
	// }

	return nil, fmt.Errorf("session: no database or session repository configured")
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
	if aus.SessionRepo != nil {
		if err := aus.SessionRepo.DeleteSession(ctx, sessionId); err != nil {
			return err
		}
	}
	// else if aus.ProvServ != nil && aus.ProvServ.GormConn != nil {
	// 	_, err := generic.DbDeleteByFilter[models.Session](gormutil.GetDB(ctx, aus.ProvServ.GormConn), ctx, models.SessionFilter{SessionId: sessionId}, nil)
	// 	if err != nil {
	// 		return err
	// 	}
	// }
	if aus.Hooks != nil {
		_ = aus.Hooks.TriggerSessionRevoked(ctx, sessionId)
	}
	return aus.BlacklistSession(ctx, sessionId)
}

func (aus Service) DeleteAllUserSessions(ctx context.Context, userId string) error {
	if aus.SessionRepo != nil {
		sessions, err := aus.SessionRepo.ListSessionsByUserID(ctx, userId)
		if err == nil {
			for _, s := range sessions {
				_ = aus.BlacklistSession(ctx, s.SessionId)
				if aus.Hooks != nil {
					_ = aus.Hooks.TriggerSessionRevoked(ctx, s.SessionId)
				}
			}
		}
		return aus.SessionRepo.DeleteSessionsByUserID(ctx, userId)
	}
	// TODO: Remove
	// if aus.ProvServ != nil && aus.ProvServ.GormConn != nil {
	// 	sessions, err := generic.DbFetchManyWithOffset[models.Session](gormutil.GetDB(ctx, aus.ProvServ.GormConn), ctx, models.SessionFilter{UserId: userId}, dtos.PaginationInput{Limit: 10000}, nil)
	// 	if err == nil {
	// 		for _, s := range sessions.Body {
	// 			_ = aus.BlacklistSession(ctx, s.SessionId)
	// 			if aus.Hooks != nil {
	// 				_ = aus.Hooks.TriggerSessionRevoked(ctx, s.SessionId)
	// 			}
	// 		}
	// 	}
	// 	_, err = generic.DbDeleteByFilter[models.Session](gormutil.GetDB(ctx, aus.ProvServ.GormConn), ctx, models.SessionFilter{UserId: userId}, nil)
	// 	return err
	// }
	return nil
}
