package services

import (
	"context"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	serv_interfaces "github.com/better-go-auth/goauth/src/app/services/interfaces"
	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins"
	interfaces1 "github.com/better-go-auth/goauth/src/plugins/access-token/services/interfaces"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
	"github.com/better-go-auth/goauth/src/providers/token"
	jwttoken "github.com/better-go-auth/goauth/src/providers/token/jwt-token"
)

// sid: -> token index is owned by the access-token plugin (not the core session.Manager).
// Core only knows token -> SessionWithUser; sid lives in the JWT claim.

func sidKey(sid string) string { return "sid:" + sid }

func isTokenLike(s string) bool {
	if len(s) < 20 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 32 || c == 127 {
			return false
		}
	}
	return true
}

func asBytes(v any) ([]byte, bool) {
	switch x := v.(type) {
	case string:
		return []byte(x), true
	case []byte:
		return x, true
	}
	return nil, false
}

func (aus *SessionService) getTokenBySID(ctx context.Context, sid string) (string, bool) {
	if aus.SStore == nil || sid == "" {
		return "", false
	}
	v, ok, err := aus.SStore.Get(ctx, sidKey(sid))
	if err != nil || !ok {
		return "", false
	}
	raw, isText := asBytes(v)
	if !isText || len(raw) == 0 {
		return "", false
	}
	tok := string(raw)
	if !isTokenLike(tok) {
		return "", false
	}
	return tok, true
}

// GetBySID resolves a session by its id via the sid: -> token secondary-storage index.
// Returns (nil, nil) on miss; falls back to Mgr.Get(token) so expiry/revocation is still enforced.
func (aus *SessionService) GetBySID(ctx context.Context, sid string) (*dtos.SessionWithUser, error) {
	tok, ok := aus.getTokenBySID(ctx, sid)
	if !ok {
		return nil, nil
	}
	return aus.Mgr.Get(ctx, tok)
}

func (aus *SessionService) setSidIndex(ctx context.Context, sid, token string, expiresAt time.Time) {
	if aus.SStore == nil || sid == "" || token == "" {
		return
	}
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return
	}
	_ = aus.SStore.Set(ctx, sidKey(sid), token, ttl)
}

func (aus *SessionService) deleteSidIndex(ctx context.Context, sid string) {
	if aus.SStore == nil || sid == "" {
		return
	}
	_ = aus.SStore.Delete(ctx, sidKey(sid))
}

// BackfillSidIndex restores sid: -> token after a DB fallback so the next request hits the cache.
// Exported for the plugin Middleware; ttl is the session's remaining lifetime.
func (aus *SessionService) BackfillSidIndex(ctx context.Context, sid, token string, ttl time.Duration) {
	if aus.SStore == nil || sid == "" || token == "" || ttl <= 0 {
		return
	}
	_ = aus.SStore.Set(ctx, sidKey(sid), token, ttl)
}

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

var _ interfaces1.IAccessTokenSessionService = (*SessionService)(nil)

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
func (aus *SessionService) Tokens(s *dtos.SessionData, role string) (*models.AuthTokens, error) {
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

// Note: CreateSession and reissue are commented out as session creation is handled
// by core Better Auth via SignInEmail/CreateSession.
// func (aus *SessionService) CreateSession(ctx context.Context, sessionId, role, userId string, opt *models.SessionOpt) (*models.AuthTokens, error) {
// 	if opt == nil {
// 		opt = &models.SessionOpt{}
// 	}
// 	orgRole := opt.OrgRole
// 	if orgRole == nil {
// 		orgRole = opt.OrgRoleID
// 	}
// 	if sessionId != "" {
// 		if existing, err := aus.SessionRepo.FindSessionByID(ctx, sessionId); err == nil && existing != nil {
// 			if existing.UserID != userId {
// 				return nil, autherr.ErrUnauthorized
// 			}
// 			return aus.reissue(ctx, existing, role, opt.ActiveOrgID, orgRole, opt.DeviceToken)
// 		}
// 	}
//
// 	user, err := aus.Users.FindUserByID(ctx, userId)
// 	if err != nil {
// 		return nil, fmt.Errorf("session: load user: %w", err)
// 	}
// 	if opt.ClearSession {
// 		_ = aus.DeleteAllUserSessions(ctx, userId)
// 	}
// 	sw, err := aus.Mgr.Create(ctx, user, sessionsvc.Meta{}, sessionsvc.CreateOptions{
// 		ID:                     sessionId,
// 		ExpiresIn:              opt.ExpiresIn,
// 		ImpersonatedBy:         opt.ImpersonatedBy,
// 		ActiveOrganizationID:   opt.ActiveOrgID,
// 		ActiveOrganizationRole: orgRole,
// 		DeviceToken:            opt.DeviceToken,
// 	})
// 	if err != nil {
// 		return nil, err
// 	}
// 	// maintain access-token's sid: -> token index
// 	if aus.SStore != nil {
// 		if sw != nil {
// 			aus.setSidIndex(ctx, sw.Session.ID, sw.Session.Token, time.Time(sw.Session.ExpiresAt))
// 		} else {
// 			// Mgr.Create didn't cache (secStore nil in core) — fall back to DB row
// 			if dbSess, err := aus.SessionRepo.FindSessionByID(ctx, sessionId); err == nil && dbSess != nil {
// 				aus.setSidIndex(ctx, dbSess.ID, dbSess.Token, dbSess.ExpiresAt)
// 			}
// 		}
// 	}
// 	s, err := aus.SessionRepo.FindSessionByID(ctx, sw.Session.ID)
// 	if err != nil {
// 		return nil, fmt.Errorf("session: load created session: %w", err)
// 	}
// 	sessionData := dtos.SessionFromModel(s)
// 	return aus.Tokens(&sessionData, role)
// }
//
// func (aus *SessionService) reissue(ctx context.Context, s *models.Session, role string, orgID, orgRole *string, deviceToken string) (*models.AuthTokens, error) {
// 	sw, err := aus.Mgr.Get(ctx, s.Token)
// 	if err != nil {
// 		return nil, err
// 	}
// 	if sw == nil {
// 		return nil, autherr.ErrSessionNotFound
// 	}
// 	data := map[string]any{"ActiveOrganizationID": orgID, "ActiveOrganizationRole": orgRole}
// 	if deviceToken != "" {
// 		data["DeviceToken"] = deviceToken
// 	}
// 	updatedSw, err := aus.Mgr.Update(ctx, sw, data)
// 	if err != nil {
// 		return nil, err
// 	}
// 	if updatedSw != nil && aus.SStore != nil {
// 		aus.setSidIndex(ctx, s.ID, updatedSw.Session.Token, time.Time(updatedSw.Session.ExpiresAt))
// 	}
// 	updated, err := aus.SessionRepo.FindSessionByID(ctx, s.ID)
// 	if err != nil {
// 		return nil, err
// 	}
// 	sessionData := dtos.SessionFromModel(updated)
// 	return aus.Tokens(&sessionData, role)
// }

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
	prevToken := s.Token
	swu, err := aus.Mgr.Get(ctx, s.Token)
	if err != nil {
		return nil, err
	}
	if swu != nil && aus.Mgr.ShouldRefresh(swu, false) {
		swu, err = aus.Mgr.Refresh(ctx, swu)
		if err != nil {
			return nil, err
		}
		if swu != nil && aus.SStore != nil {
			aus.setSidIndex(ctx, s.ID, swu.Session.Token, time.Time(swu.Session.ExpiresAt))
		}
	}
	if swu != nil && aus.SConf.JWT.RotatesRefreshToken() {
		swu, err = aus.Mgr.RotateToken(ctx, swu)
		if err != nil {
			return nil, err
		}
		if swu != nil && aus.SStore != nil {
			if prevToken != "" && prevToken != swu.Session.Token {
				aus.deleteSidIndex(ctx, s.ID)
			}
			aus.setSidIndex(ctx, s.ID, swu.Session.Token, time.Time(swu.Session.ExpiresAt))
		}
	}
	if swu == nil {
		return nil, autherr.ErrInvalidToken
	}
	updated, err := aus.SessionRepo.FindSessionByID(ctx, swu.Session.ID)
	if err != nil {
		return nil, err
	}
	sessionData := dtos.SessionFromModel(updated)
	return aus.Tokens(&sessionData, role)
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
		if aus.SStore != nil {
			aus.deleteSidIndex(ctx, sessionId)
		}
	}
	if aus.Hooks != nil {
		_ = aus.Hooks.TriggerSessionRevoked(ctx, sessionId)
	}
	return aus.BlacklistSession(ctx, sessionId)
}

