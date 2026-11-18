package accesstoken

import (
	"context"
	"net/http"
	"strings"

	humaadapter "github.com/better-go-auth/goauth/src/app/adapters/huma"
	"github.com/better-go-auth/goauth/src/config"
	humaaccesstoken "github.com/better-go-auth/goauth/src/plugins/access-token/adapters/huma"
	jwttoken "github.com/better-go-auth/goauth/src/plugins/access-token/jwttoken"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	"github.com/danielgtaylor/huma/v2"
)

// signOutCredential is the session an access-token client signs out of.
type signOutCredential struct {
	// token is the session token (== refresh token) core sign-out must revoke.
	token string
	// sessionID is the id of that session ("" when it was not looked up).
	sessionID string
}

// accessSecretFor returns the key that signs access JWTs: the configured AccessSecret, else a key derived
// from the core secret, else the core secret itself.
func (p *Plugin) accessSecretFor(authCfg config.AuthConfig) string {
	accessSecret := p.sessionConf.JWT.AccessSecret
	if accessSecret == "" && authCfg.Secret != "" {
		accessSecret = config.DeriveKey(authCfg.Secret, "goauth-access")
	}
	if accessSecret == "" {
		accessSecret = authCfg.Secret
	}
	return accessSecret
}

// buildSignOutMiddleware returns a Huma middleware that lets access-token clients log out through the core
// POST {basePath}/sign-out route. It is registered on every API the plugin is mounted on (whatever
// AutoRegisterMiddleware says) and does nothing for any other operation.
//
// Core sign-out only reads the better-auth session cookie (or a bearer token another transport resolved), so
// the middleware turns the access-token credentials into that cookie: it finds the session behind
// "Authorization: Bearer <access JWT>", "Authorization: Bearer <refresh token>", the refresh-token cookie or
// the access-token cookie (in that order) and injects its signed session cookie into the request. Core
// sign-out then deletes the session and fires OnSessionRevoked, which blacklists the session id so access JWTs
// issued for it stop working before they expire. The access-token / refresh-token cookies are expired in the
// same response.
func (p *Plugin) buildSignOutMiddleware(authCfg config.AuthConfig, attrs humaaccesstoken.CookieAttrs) func(ctx huma.Context, next func(huma.Context)) {
	cm := cookies.New(authCfg)
	accessSecret := p.accessSecretFor(authCfg)
	signOutOp := humaadapter.OpSignOut.Str()

	return func(ctx huma.Context, next func(huma.Context)) {
		// Step 1: only the core sign-out operation is handled here
		if op := ctx.Operation(); op == nil || op.OperationID != signOutOp {
			next(ctx)
			return
		}

		// Step 2: find the session behind the access-token credentials of the request
		cred, usedPluginCreds := p.signOutCredential(ctx, accessSecret)

		// Step 3: hand the session to core sign-out
		revokeAfter := false
		if cred != nil && cred.token != "" {
			ctx, revokeAfter = p.handOverToCoreSignOut(ctx, cm, cred)
		}

		// Step 4: expire the plugin's own cookies. Headers appended before the handler runs are kept, since
		// Huma only appends its Set-Cookie entries when the handler answers.
		if usedPluginCreds {
			for _, name := range []string{humaaccesstoken.AccessTokenCookie, humaaccesstoken.RefreshTokenCookie} {
				ck := humaaccesstoken.ExpireCookie(name, attrs)
				ctx.AppendHeader("Set-Cookie", ck.String())
			}
		}

		// Step 5: run core sign-out
		next(ctx)

		// Step 6: core signed out another session (the request's session cookie); revoke ours as well, but
		// only once core accepted the request, so the origin / CSRF checks guard this revocation too
		if revokeAfter && ctx.Status() > 0 && ctx.Status() < http.StatusBadRequest {
			p.revokeSessionDirectly(ctx.Context(), cred)
		}
	}
}

// signOutCredential resolves the session to sign out of from, in order: a Bearer access JWT, a Bearer refresh
// token, the refresh-token cookie and the access-token cookie. usedPluginCreds reports whether the request
// carried access-token credentials (so their cookies should be expired), even when they no longer resolve.
func (p *Plugin) signOutCredential(ctx huma.Context, accessSecret string) (cred *signOutCredential, usedPluginCreds bool) {
	reqCtx := ctx.Context()

	// Step 1: the plugin cookies; their mere presence means the response must expire them
	var refreshCookie, accessCookie string
	if parsed, err := http.ParseCookie(ctx.Header("Cookie")); err == nil {
		for _, ck := range parsed {
			switch ck.Name {
			case humaaccesstoken.RefreshTokenCookie:
				refreshCookie = ck.Value
			case humaaccesstoken.AccessTokenCookie:
				accessCookie = ck.Value
			}
		}
	}
	usedPluginCreds = refreshCookie != "" || accessCookie != ""

	// Step 2: "Authorization: Bearer <token>"
	authHeader := ctx.Header("Authorization")
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		raw := strings.TrimSpace(authHeader[7:])
		isJWT := strings.Count(raw, ".") == 2
		// 2a. another transport (the global access-token middleware for JWTs, the bearer plugin for session
		// tokens) already resolved the bearer token: core sign-out reads it from the context, no second lookup
		if btok, ok := humaadapter.FromBearerContext(reqCtx); ok {
			return &signOutCredential{token: btok}, usedPluginCreds || isJWT
		}
		switch {
		case raw == "":
		case isJWT:
			// 2b. access JWT: verify it and look up its live session by the sid claim
			if c := p.sessionFromAccessJWT(reqCtx, raw, accessSecret); c != nil {
				return c, true
			}
		default:
			// 2c. refresh token (the session token itself, raw or signed)
			if c := p.sessionFromRefreshToken(reqCtx, raw); c != nil {
				return c, true
			}
		}
	}

	// Step 3: the refresh-token cookie
	if refreshCookie != "" {
		if c := p.sessionFromRefreshToken(reqCtx, refreshCookie); c != nil {
			return c, true
		}
	}

	// Step 4: the access-token cookie
	if accessCookie != "" && strings.Count(accessCookie, ".") == 2 {
		if c := p.sessionFromAccessJWT(reqCtx, accessCookie, accessSecret); c != nil {
			return c, true
		}
	}
	return nil, usedPluginCreds
}

// sessionFromAccessJWT validates an access JWT and returns the live session it names, or nil.
func (p *Plugin) sessionFromAccessJWT(ctx context.Context, raw, accessSecret string) *signOutCredential {
	// Step 1: verify signature, expiry and type
	claims, err := jwttoken.ValidateAccessToken(raw, accessSecret)
	if err != nil || claims == nil || claims.SessionID == "" {
		return nil
	}
	// Step 2: the session must still be alive (not blacklisted, not expired)
	sessWithUsr, tok := p.resolveLiveSessionByID(ctx, claims.SessionID, false)
	if sessWithUsr == nil {
		return nil
	}
	if tok == "" {
		tok = sessWithUsr.Session.Token
	}
	return &signOutCredential{token: tok, sessionID: claims.SessionID}
}

// sessionFromRefreshToken returns the live session behind a refresh token, or nil.
func (p *Plugin) sessionFromRefreshToken(ctx context.Context, refreshToken string) *signOutCredential {
	if p.sessionSvc == nil {
		return nil
	}
	sess, err := p.sessionSvc.FindByRefreshToken(ctx, refreshToken)
	if err != nil || sess == nil || sess.Token == "" {
		return nil
	}
	return &signOutCredential{token: sess.Token, sessionID: sess.ID}
}

// handOverToCoreSignOut makes core sign-out revoke cred's session: it injects the signed session cookie into
// the request (and the token into the bearer context). When the request already carries a valid session cookie
// of another session, core signs that one out and revokeAfter tells the caller to revoke cred's session once
// core sign-out succeeded.
func (p *Plugin) handOverToCoreSignOut(ctx huma.Context, cm *cookies.Manager, cred *signOutCredential) (huma.Context, bool) {
	// Step 1: a session cookie of another session wins in core sign-out: ours is revoked after it
	if existing, ok := cm.SessionToken(ctx.Header("Cookie")); ok {
		return ctx, existing != cred.token
	}

	// Step 2: inject the signed session cookie, which core sign-out reads first
	if r, _ := safeHumagoUnwrap(ctx); r != nil {
		injectCookieHeader(r, cm.Name(cookies.CookieSessionToken), cm.Signed(cred.token))
	}

	// Step 3: also expose the token as the bearer token core sign-out falls back to (non-humago adapters)
	if _, ok := humaadapter.FromBearerContext(ctx.Context()); !ok {
		ctx = huma.WithContext(ctx, humaadapter.WithBearerToken(ctx.Context(), cred.token))
	}
	return ctx, false
}

// revokeSessionDirectly deletes cred's session through the plugin's session service (DB row, cache, sid index,
// OnSessionRevoked hooks and access-token blacklist).
func (p *Plugin) revokeSessionDirectly(ctx context.Context, cred *signOutCredential) {
	if p.sessionSvc == nil {
		return
	}
	// Step 1: resolve the session id when only the token is known
	sessionID := cred.sessionID
	if sessionID == "" && p.repos != nil {
		if s, _ := p.repos.FindSession(ctx, cred.token); s != nil {
			sessionID = s.ID
		}
	}
	if sessionID == "" {
		return
	}
	// Step 2: delete it; like core sign-out, a failed delete does not fail the request
	_ = p.sessionSvc.DeleteSession(ctx, sessionID)
}
