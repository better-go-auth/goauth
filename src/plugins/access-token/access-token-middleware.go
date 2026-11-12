package accesstoken

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	humaadapter "github.com/better-go-auth/goauth/src/app/adapters/huma"
	constant "github.com/better-go-auth/goauth/src/common/consts"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	"github.com/better-go-auth/goauth/src/providers/idgen"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
	"github.com/better-go-auth/goauth/src/providers/token"
	jwttoken "github.com/better-go-auth/goauth/src/providers/token/jwt-token"
	"github.com/danielgtaylor/huma/v2"
)

func (p *Plugin) buildMiddleware(authCfg config.AuthConfig) func(ctx huma.Context, next func(huma.Context)) {
	cm := cookies.New(authCfg)
	cookieName := cm.Name(cookies.CookieSessionToken)
	accessSecret := p.sessionConf.JWT.AccessSecret
	if accessSecret == "" && authCfg.Secret != "" {
		accessSecret = config.DeriveKey(authCfg.Secret, "goauth-access")
	}
	if accessSecret == "" {
		accessSecret = authCfg.Secret
	}
	bearerOnlySet := config.OperationSet(p.config.RequireBearerTokenOps)
	rejectBlocked := p.config.RejectBlockedAccessTokens

	return func(ctx huma.Context, next func(huma.Context)) {
		authHeader := ctx.Header("Authorization")
		if authHeader == "" {
			authHeader = ctx.Header("authorization")
		}

		var refreshedTokenCtx huma.Context
		if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			raw := strings.TrimSpace(authHeader[7:])
			// if the raw is a jwt token verify and attach the session with the request
			if raw != "" && strings.Count(raw, ".") == 2 {
				// 0. Skip or reject Access JWTs on operations configured to require a stateful session / bearer token
				if len(bearerOnlySet) > 0 {
					if op := ctx.Operation(); op != nil && bearerOnlySet[op.OperationID] {
						if rejectBlocked {
							ctx.SetStatus(http.StatusUnauthorized)
							ctx.SetHeader("Content-Type", "application/json")
							_ = json.NewEncoder(ctx.BodyWriter()).Encode(map[string]any{
								"code":    "UNAUTHORIZED",
								"message": "access token not allowed for this operation",
							})
							return
						}
						next(ctx)
						return
					}
				}
				// 1. Verify access JWT
				claims, err := jwttoken.ValidateAccessToken(raw, accessSecret)
				if err == nil && claims != nil && claims.SessionID != "" {
					// Snapshot the org/role/team claims from the incoming JWT BEFORE Layer 1 syncs them
					// from the live session, so Layer 2 can later detect if the JWT is out of date.
					tokenOrgID := claims.ActiveOrgId
					tokenOrgRole := claims.ActiveOrgRole
					tokenTeamID := claims.ActiveTeamId

					// 2. Revocation check + live session lookup (cache fast-path with DB fallback)
					sessWithUsr, sessToken := p.resolveLiveSessionByID(ctx.Context(), claims.SessionID, true)
					// put the session user in the context
					if sessWithUsr != nil {
						tok := sessToken
						if tok == "" {
							tok = sessWithUsr.Session.Token
						}

						// Layer 1 fix: Sync JWT claims with live session active org/role/team
						// so subsequent requests with an older JWT immediately reflect session state.
						syncClaimsFromSession(claims, &sessWithUsr.Session)

						// Attach to context
						stdCtx := ctx.Context()
						stdCtx = humaadapter.WithSession(stdCtx, sessWithUsr)
						stdCtx = humaadapter.WithBearerToken(stdCtx, tok)
						stdCtx = context.WithValue(stdCtx, constant.CtxClaims.Str(), *claims)
						stdCtx = context.WithValue(stdCtx, constant.CTXUser_ID.Str(), claims.UserID)
						if claims.ActiveOrgId != "" {
							stdCtx = context.WithValue(stdCtx, constant.CTXCompany_ID.Str(), claims.ActiveOrgId)
						}
						ctx = huma.WithContext(ctx, stdCtx)
						// add token from the session to cookie
						if idgen.IsToken(tok) {
							signedCookieVal := cm.Signed(tok)
							if r, _ := safeHumagoUnwrap(ctx); r != nil {
								injectCookieHeader(r, cookieName, signedCookieVal)
							}
						}

						// Layer 2 fix: Wrap huma.Context so onBeforeWrite runs right after the handler finishes
						// (before SetStatus/BodyWriter flushes HTTP headers). By comparing the live session's
						// org/role/team against the incoming JWT snapshot, any route that mutates them (e.g.
						// SetActiveOrganization / SetActiveTeam) automatically returns a fresh set-auth-token.
						if p.sessionSvc != nil {
							sessionID := claims.SessionID
							innerCtx := ctx
							wrapped := &accessTokenContextWrapper{
								inner: innerCtx,
								onBeforeWrite: func() {
									// 1. Re-fetch the live session from cache/DB after the handler ran
									latest, _ := p.resolveLiveSessionByID(innerCtx.Context(), sessionID, false)
									if latest == nil {
										return
									}
									// 2. Diff live session state against the incoming JWT's org/role/team snapshot
									curOrgID := derefStr(latest.Session.ActiveOrganizationID)
									curOrgRole := derefStr(latest.Session.ActiveOrganizationRole)
									curTeamID := derefStr(latest.Session.ActiveTeamID)
									if curOrgID == tokenOrgID && curOrgRole == tokenOrgRole && curTeamID == tokenTeamID {
										return
									}
									// 3. Mint a new Access JWT reflecting the updated session claims
									tokens, tokErr := p.sessionSvc.Tokens(&latest.Session, latest.User.Role)
									if tokErr != nil || tokens == nil || tokens.AccessToken == "" {
										return
									}
									// 4. Write set-auth-token (and expose it for CORS) on both Huma context and ResponseWriter
									innerCtx.SetHeader("set-auth-token", tokens.AccessToken)
									curExp := innerCtx.Header("Access-Control-Expose-Headers")
									innerCtx.SetHeader("Access-Control-Expose-Headers", appendExposedHeader(curExp, "set-auth-token"))
									if _, hw := safeHumagoUnwrap(innerCtx); hw != nil {
										hw.Header().Set("set-auth-token", tokens.AccessToken)
										hwExp := hw.Header().Get("Access-Control-Expose-Headers")
										hw.Header().Set("Access-Control-Expose-Headers", appendExposedHeader(hwExp, "set-auth-token"))
									}
								},
							}
							refreshedTokenCtx = wrapped
						}
					}
				}
			}
		}

		if refreshedTokenCtx != nil {
			next(refreshedTokenCtx)
			if w, ok := refreshedTokenCtx.(*accessTokenContextWrapper); ok {
				w.flush()
			}
			return
		}
		next(ctx)
	}
}

// resolveLiveSessionByID after a jwt token is verified, gets the token by session.id and checks if it is revoked
func (p *Plugin) resolveLiveSessionByID(ctx context.Context, sessionID string, populateCache bool) (*dtos.SessionWithUser, string) {
	// Step 1: Reject blacklisted sessions
	if p.secStorage != nil {
		if _, exists, _ := p.secStorage.Get(ctx, sec_storage.RevokedSessionPrefix+sessionID); exists {
			return nil, ""
		}
	}
	// Step 2: Fast-path via sid: -> token cache index
	if p.sessionSvc != nil {
		if cached, _ := p.sessionSvc.GetBySID(ctx, sessionID); cached != nil {
			return cached, cached.Session.Token
		}
	}
	// Step 3: Fallback to DB session lookup
	if p.repos == nil {
		return nil, ""
	}
	sess, err := p.repos.FindSessionByID(ctx, sessionID)
	if err != nil || sess == nil || !sess.ExpiresAt.After(time.Now()) {
		return nil, ""
	}
	var sessWithUsr *dtos.SessionWithUser
	if p.sessionMgr != nil {
		sessWithUsr, _ = p.sessionMgr.Get(ctx, sess.Token)
	}
	if sessWithUsr == nil {
		u, err := p.repos.FindUserByID(ctx, sess.UserID)
		if err == nil && u != nil {
			sessWithUsr = &dtos.SessionWithUser{
				Session: dtos.SessionFromModel(sess),
				User:    dtos.UserFromModel(u),
			}
		}
	}
	if sessWithUsr != nil && populateCache {
		ttl := time.Until(sess.ExpiresAt)
		if ttl > 0 {
			if p.sessionSvc != nil {
				p.sessionSvc.BackfillSidIndex(ctx, sess.ID, sess.Token, ttl)
			} else if p.secStorage != nil {
				_ = p.secStorage.Set(ctx, SidPrefix+sess.ID, sess.Token, ttl)
			}
		}
	}
	return sessWithUsr, sess.Token
}

func syncClaimsFromSession(claims *token.CustomClaims, sess *dtos.SessionData) {
	if claims == nil || sess == nil {
		return
	}
	claims.ActiveOrgId = derefStr(sess.ActiveOrganizationID)
	claims.ActiveOrgRole = derefStr(sess.ActiveOrganizationRole)
	claims.ActiveTeamId = derefStr(sess.ActiveTeamID)
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
