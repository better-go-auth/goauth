package humaadapter

import (
	"context"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	autherr "github.com/better-go-auth/goauth/src/common/errors"
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
	// role and org role are not part of the better-auth session snapshot
	if u, err := r.repos.FindUserByID(ctx, sw.User.ID); err == nil && u != nil {
		claims.Role = string(u.Role)
	}
	if s, err := r.repos.FindSessionByID(ctx, sw.Session.ID); err == nil && s != nil && s.ActiveOrganizationRole != nil {
		claims.ActiveOrgRole = *s.ActiveOrganizationRole
	}
	return claims, nil
}
