package humaadapter

import (
	"context"
	"log/slog"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	"github.com/better-go-auth/goauth/src/providers/token"
)

// SessionClaims implements middleware.SessionClaimsResolver: it lets the legacy auth middleware accept a
// better-auth session token (raw bearer token or signed session cookie) in place of an access JWT.
type SessionClaims struct {
	mgr     *sessionsvc.Manager
	cookies *cookies.Manager
	repos   repo_interfaces.IAuthRepos
}

func NewSessionClaims(mgr *sessionsvc.Manager, cm *cookies.Manager, repos repo_interfaces.IAuthRepos) *SessionClaims {
	return &SessionClaims{mgr: mgr, cookies: cm, repos: repos}
}

func (r *SessionClaims) ClaimsFromSession(ctx context.Context, bearer, cookieHeader string) (*token.CustomClaims, error) {
	tok := bearer
	if tok == "" {
		tok, _ = r.cookies.SessionToken(cookieHeader)
	}
	if tok == "" {
		return nil, autherr.ErrUnauthorized
	}
	sw, err := r.mgr.Get(ctx, tok)
	if err != nil || sw == nil {
		return nil, autherr.ErrUnauthorized
	}
	claims := &token.CustomClaims{UserID: sw.User.ID, SessionID: sw.Session.ID, Type: token.TypeAccess}
	if sw.Session.ActiveOrganizationID != nil {
		claims.ActiveOrgId = *sw.Session.ActiveOrganizationID
	}
	if sw.Session.ActiveTeamID != nil {
		claims.ActiveTeamId = *sw.Session.ActiveTeamID
	}
	// Fast path: use role and org role from session snapshot; fallback to DB only if missing
	if sw.User.Role != "" {
		claims.Role = string(sw.User.Role)
	} else if r.repos != nil {
		if u, err := r.repos.FindUserByID(ctx, sw.User.ID); err == nil && u != nil {
			claims.Role = string(u.Role)
		} else if err != nil {
			slog.Debug("session_claims: FindUserByID failed, using cached role", "err", err)
		}
	}
	//
	if sw.Session.ActiveOrganizationRole != nil && *sw.Session.ActiveOrganizationRole != "" {
		claims.ActiveOrgRole = *sw.Session.ActiveOrganizationRole
	} else if r.repos != nil && claims.ActiveOrgId != "" {
		if s, err := r.repos.FindSessionByID(ctx, sw.Session.ID); err == nil && s != nil && s.ActiveOrganizationRole != nil {
			claims.ActiveOrgRole = *s.ActiveOrganizationRole
		} else if err != nil {
			slog.Debug("session_claims: FindSessionByID failed, org role may be stale", "err", err)
		}
	}
	return claims, nil
}
