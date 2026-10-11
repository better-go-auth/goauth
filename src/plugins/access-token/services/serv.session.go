package services

import (
	"context"
	"fmt"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	serv_interfaces"github.com/better-go-auth/goauth/src/app/services/interfaces"
	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
	"github.com/better-go-auth/goauth/src/providers/token"
	jwttoken "github.com/better-go-auth/goauth/src/providers/token/jwt-token"
)

// SessionService is the legacy JWT transport on top of the shared better-auth sessions: every login is a normal
// session row, the refresh token is that session's token, and the access token is a short JWT with sid = session id.
type SessionService struct {
	SessionRepo repo_interfaces.ISessionRepo
	Users       repo_interfaces.IUserRepo
	Mgr         serv_interfaces.ISessionManager
	SConf       config.SessionGoAuth
	SStore      sec_storage.SecondaryStorage
	Hooks       plugins.HookRegistry
}

var _ IAccessTokenSessionService = (*SessionService)(nil)

// NewSessionService builds the legacy session service; mgr is the shared session manager (goauth.GoAuth.Sessions).
func NewSessionService(
	conf config.SessionGoAuth,
	repos repo_interfaces.IAuthRepos,
	mgr serv_interfaces.ISessionManager,
	sStore sec_storage.SecondaryStorage,
	hooks ...plugins.HookRegistry,
) *SessionService {
	if repos == nil || mgr == nil {
		panic("session: repositories and session manager are required")
	}
	var h plugins.HookRegistry
	if len(hooks) > 0 {
		h = hooks[0]
	}
	return &SessionService{
		SessionRepo: repos,
		Users:       repos,
		Mgr:         mgr,
		SConf:       conf,
		SStore:      sStore,
		Hooks:       h,
	}
}

// tokens signs the access JWT for s and returns it with the session token as the refresh token.
func (aus *SessionService) Tokens(s *models.Session, role string) (*models.AuthTokens, error) {
	claims := token.CustomClaims{
		Role:      role,
		UserID:    s.UserID,
		SessionID: s.ID,
		Type:      token.TypeAccess,
	}
	if s.ActiveOrganizationID != nil {
		claims.ActiveOrgId = *s.ActiveOrganizationID
	}
	if s.ActiveOrganizationRole != nil {
		claims.ActiveOrgRole = *s.ActiveOrganizationRole
	}
	access, err := jwttoken.SignWithExpiry(aus.SConf.JWT.AccessSecret, &claims, aus.SConf.JWT.AccessExpiresIn)
	if err != nil {
		return nil, err
	}
	return &models.AuthTokens{AccessToken: access, RefreshToken: s.Token}, nil
}

// CreateSession starts a session and returns its tokens. If sessionId already names one of the user's sessions
// (e.g. the org plugin switching the active organization), that session is updated and re-issued instead.
func (aus *SessionService) CreateSession(ctx context.Context, sessionId, role, userId string, opt *models.SessionOpt) (*models.AuthTokens, error) {
	if opt == nil {
		opt = &models.SessionOpt{}
	}
	orgRole := opt.OrgRole
	if orgRole == nil {
		orgRole = opt.OrgRoleID
	}
	if sessionId != "" {
		if existing, err := aus.SessionRepo.FindSessionByID(ctx, sessionId); err == nil && existing != nil {
			if existing.UserID != userId {
				return nil, autherr.ErrUnauthorized
			}
			return aus.reissue(ctx, existing, role, opt.ActiveOrgID, orgRole, opt.DeviceToken)
		}
	}

	user, err := aus.Users.FindUserByID(ctx, userId)
	if err != nil {
		return nil, fmt.Errorf("session: load user: %w", err)
	}
	if opt.ClearSession {
		_ = aus.DeleteAllUserSessions(ctx, userId)
	}
	sw, err := aus.Mgr.Create(ctx, user, sessionsvc.Meta{}, sessionsvc.CreateOptions{
		ID:                     sessionId,
		ExpiresIn:              opt.ExpiresIn,
		ImpersonatedBy:         opt.ImpersonatedBy,
		ActiveOrganizationID:   opt.ActiveOrgID,
		ActiveOrganizationRole: orgRole,
		DeviceToken:            opt.DeviceToken,
	})
	if err != nil {
		return nil, err
	}
	s, err := aus.SessionRepo.FindSessionByID(ctx, sw.Session.ID)
	if err != nil {
		return nil, fmt.Errorf("session: load created session: %w", err)
	}
	return aus.Tokens(s, role)
}

// reissue writes the org context (nil clears it) and device token onto an existing session and signs new tokens.
func (aus *SessionService) reissue(ctx context.Context, s *models.Session, role string, orgID, orgRole *string, deviceToken string) (*models.AuthTokens, error) {
	sw, err := aus.Mgr.Get(ctx, s.Token)
	if err != nil {
		return nil, err
	}
	if sw == nil {
		return nil, autherr.ErrSessionNotFound
	}
	data := map[string]any{"ActiveOrganizationID": orgID, "ActiveOrganizationRole": orgRole}
	if deviceToken != "" {
		data["DeviceToken"] = deviceToken
	}
	if _, err := aus.Mgr.Update(ctx, sw, data); err != nil {
		return nil, err
	}
	updated, err := aus.SessionRepo.FindSessionByID(ctx, s.ID)
	if err != nil {
		return nil, err
	}
	return aus.Tokens(updated, role)
}

// FindByRefreshToken returns the live session behind a refresh token, or nil (unknown, expired or revoked).
func (aus *SessionService) FindByRefreshToken(ctx context.Context, refreshToken string) (*models.Session, error) {
	sw, err := aus.Mgr.Get(ctx, refreshToken)
	if err != nil || sw == nil {
		return nil, err
	}
	return aus.SessionRepo.FindSessionByID(ctx, sw.Session.ID)
}

// RefreshTokens slides the session's expiry like better-auth (once UpdateAge has passed), rotates the refresh
// token when GoAuth.Session.JWT.RotateRefreshToken is on (default) and signs a new access token.
func (aus *SessionService) RefreshTokens(ctx context.Context, s *models.Session, role string) (*models.AuthTokens, error) {
	swu, err := aus.Mgr.Get(ctx, s.Token)
	if err != nil {
		return nil, err
	}
	if swu != nil && aus.Mgr.ShouldRefresh(swu, false) {
		swu, err = aus.Mgr.Refresh(ctx, swu)
		if err != nil {
			return nil, err
		}
	}
	if swu != nil && aus.SConf.JWT.RotatesRefreshToken() {
		swu, err = aus.Mgr.RotateToken(ctx, swu)
		if err != nil {
			return nil, err
		}
	}
	if swu == nil {
		return nil, autherr.ErrInvalidToken
	}
	updated, err := aus.SessionRepo.FindSessionByID(ctx, swu.Session.ID)
	if err != nil {
		return nil, err
	}
	return aus.Tokens(updated, role)
}

// BlacklistSession marks a session id as revoked in secondary storage, so access JWTs that carry it are
// rejected before they expire even when CheckRevocation is off.
func (aus *SessionService) BlacklistSession(ctx context.Context, sessionId string) error {
	if aus.SStore == nil {
		return nil
	}
	ttl := aus.SConf.JWT.AccessExpiresIn
	if ttl <= 0 {
		ttl = time.Hour
	}
	return aus.SStore.Set(ctx, "blacklist:"+sessionId, "blacklisted", ttl)
}

// DeleteSession revokes one session by id (DB row, cached copy and its access tokens).
func (aus *SessionService) DeleteSession(ctx context.Context, sessionId string) error {
	s, err := aus.SessionRepo.FindSessionByID(ctx, sessionId)
	if err == nil && s != nil {
		if err := aus.Mgr.Delete(ctx, s.Token); err != nil {
			return err
		}
	}
	if aus.Hooks != nil {
		_ = aus.Hooks.TriggerSessionRevoked(ctx, sessionId)
	}
	return aus.BlacklistSession(ctx, sessionId)
}

// DeleteAllUserSessions revokes every session of userId.
func (aus *SessionService) DeleteAllUserSessions(ctx context.Context, userId string) error {
	if sessions, err := aus.SessionRepo.ListSessions(ctx, userId); err == nil {
		for _, s := range sessions {
			_ = aus.BlacklistSession(ctx, s.ID)
			if aus.Hooks != nil {
				_ = aus.Hooks.TriggerSessionRevoked(ctx, s.ID)
			}
		}
	}
	return aus.Mgr.DeleteUserSessions(ctx, userId)
}
