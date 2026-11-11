package accesstoken

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	authint "github.com/better-go-auth/goauth/src/app/services/interfaces"

	humaadapter "github.com/better-go-auth/goauth/src/app/adapters/huma"
	constant "github.com/better-go-auth/goauth/src/common/consts"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	"github.com/better-go-auth/goauth/src/common/middleware"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	humaaccesstoken "github.com/better-go-auth/goauth/src/plugins/access-token/adapters/huma"
	accesstokenconfig "github.com/better-go-auth/goauth/src/plugins/access-token/config"
	"github.com/better-go-auth/goauth/src/plugins/access-token/services"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	"github.com/better-go-auth/goauth/src/providers/idgen"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
	"github.com/better-go-auth/goauth/src/providers/token"
	jwttoken "github.com/better-go-auth/goauth/src/providers/token/jwt-token"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
)

func safeHumagoUnwrap(ctx huma.Context) (r *http.Request, w http.ResponseWriter) {
	defer func() {
		_ = recover()
	}()
	return humago.Unwrap(ctx)
}

const PluginID = "access-token"

// Plugin implements plugins.Plugin for legacy access-token / JWT authentication.
type Plugin struct {
	config      accesstokenconfig.AccessTokenConfig
	basePath    string
	sessionConf accesstokenconfig.SessionGoAuth
	//
	vConf     config.EmailVerification
	passwords *authcrypto.Passwords

	authSvc    *services.AuthService
	sessionSvc *services.SessionService
	vSvc       *services.VerificationService
	//
	handler *humaaccesstoken.AccessTokenHandler

	repos      repo_interfaces.IAuthRepos
	sessionMgr authint.ISessionManager
	IAuthSvc   authint.IAuthService
	secStorage sec_storage.SecondaryStorage
	txMgr      interfaces.ITransactionManager
	authConfig config.AuthConfig
	middleware func(ctx huma.Context, next func(huma.Context))
}

var _ plugins.Plugin = (*Plugin)(nil)

// Option configures the access-token Plugin.
type Option func(*Plugin)

// WithConfig sets the entire AccessTokenConfig.
func WithConfig(conf accesstokenconfig.AccessTokenConfig) Option {
	return func(p *Plugin) {
		p.config = conf
		p.sessionConf = conf.Session
	}
}

// WithBasePath sets custom base path (e.g. "/api/auth").
func WithBasePath(basePath string) Option {
	return func(p *Plugin) {
		p.basePath = basePath
	}
}

// WithSessionConfig sets session settings for JWT.
func WithSessionConfig(conf accesstokenconfig.SessionGoAuth) Option {
	return func(p *Plugin) {
		p.sessionConf = conf
		p.config.Session = conf
	}
}

// WithVerificationConfig sets email verification configuration.
func WithVerificationConfig(conf config.EmailVerification) Option {
	return func(p *Plugin) {
		p.vConf = conf
	}
}

// WithPasswords sets a pre-configured Passwords hasher.
func WithPasswords(passwords *authcrypto.Passwords) Option {
	return func(p *Plugin) {
		p.passwords = passwords
	}
}

// WithAutoRegisterMiddleware configures whether the plugin automatically registers its middleware globally on the Huma API.
func WithAutoRegisterMiddleware(auto bool) Option {
	return func(p *Plugin) {
		p.config.AutoRegisterMiddleware = auto
	}
}

// New creates a new access-token Plugin.
// Directly accepts the config struct so users can configure it directly (mimicking Better Auth's plugin pattern),
// with functional options supported as additional optional overrides.
func New(cfg accesstokenconfig.AccessTokenConfig, opts ...Option) *Plugin {
	defaultCfg := accesstokenconfig.DefaultAccessTokenConfig()
	if cfg.Session.JWT.AccessExpiresIn <= 0 {
		cfg.Session.JWT.AccessExpiresIn = defaultCfg.Session.JWT.AccessExpiresIn
	}

	p := &Plugin{
		config:      cfg,
		sessionConf: cfg.Session,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// ID returns the unique identifier of the plugin.
func (p *Plugin) ID() string {
	return PluginID
}

// SessionConfig returns the session and JWT configuration of the access-token plugin.
func (p *Plugin) SessionConfig() accesstokenconfig.SessionGoAuth {
	return p.sessionConf
}

// Init initializes services and mounts Huma routes if API is provided in InitContext.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	if ictx == nil {
		return fmt.Errorf("access-token plugin: init context is required")
	}

	repos := ictx.IAuthRepos
	if repos == nil {
		return fmt.Errorf("access-token plugin: IAuthRepos is required")
	}
	p.repos = repos

	// Resolve transaction manager
	txMgr := ictx.TxManager
	if txMgr == nil && ictx.DB != nil {
		txMgr = gormutil.NewGormTxManager(ictx.DB)
	}
	p.txMgr = txMgr

	p.sessionMgr = ictx.SessionManager

	// Resolve secondary storage
	secStorage := ictx.SecondaryStorage
	p.secStorage = secStorage

	// Resolve configs
	sConf := p.sessionConf
	if sConf.JWT.AccessSecret == "" && ictx.Config.Secret != "" {
		sConf.JWT.AccessSecret = config.DeriveKey(ictx.Config.Secret, "goauth-access")
	}
	if sConf.JWT.AccessExpiresIn <= 0 {
		sConf.JWT.AccessExpiresIn = 15 * time.Minute
	}
	// Fallback to core Session.GoAuth if not explicitly customized
	if sConf.UpdatableFields == nil {
		sConf.UpdatableFields = ictx.Config.Session.GoAuth.UpdatableFields
	}
	if !sConf.SingleSession {
		sConf.SingleSession = ictx.Config.Session.GoAuth.SingleSession
	}
	p.sessionConf = sConf

	vConf := p.vConf
	if vConf.GoAuth.CodeSender == nil && ictx.Config.EmailVerification.GoAuth.CodeSender != nil {
		vConf = ictx.Config.EmailVerification
	}
	p.vConf = vConf

	if p.basePath == "" {
		p.basePath = ictx.Config.BasePath
	}
	if p.basePath == "" {
		p.basePath = "/api/auth"
	}

	if p.passwords == nil {
		p.passwords = authcrypto.NewPasswords(ictx.Config)
	}

	// 1. Initialize services
	sessMgr := ictx.SessionManager
	coreAuthSvc := ictx.IAuthSvc
	if coreAuthSvc == nil {
		return fmt.Errorf("access-token plugin: IAuthSvc is required")
	}
	p.IAuthSvc = coreAuthSvc
	// initialize the legacy services
	p.vSvc = services.NewVerificationService(repos, vConf)
	p.sessionSvc = services.NewSessionService(sConf, repos, sessMgr, secStorage, ictx.Hooks)
	p.sessionSvc.Secret = ictx.Config.Secret
	p.authSvc = services.NewAuthService(&sConf, coreAuthSvc, p.vSvc, p.sessionSvc, repos, txMgr, p.passwords, ictx.Hooks)

	// Register lifecycle hook to blacklist session and clean up sid index upon revocation
	if ictx.Hooks != nil {
		ictx.Hooks.OnSessionRevoked(func(ctx context.Context, session *models.Session) error {
			if session == nil {
				return nil
			}
			sessionID := session.ID
			if sessionID == "" && session.Token != "" && p.repos != nil {
				if s, _ := p.repos.FindSession(ctx, session.Token); s != nil {
					sessionID = s.ID
				}
			}
			if sessionID == "" {
				return nil
			}
			if p.sessionSvc != nil {
				return p.sessionSvc.BlacklistSession(ctx, sessionID)
			}
			if p.secStorage != nil {
				ttl := p.sessionConf.JWT.AccessExpiresIn
				if ttl <= 0 {
					ttl = time.Hour
				}
				_ = p.secStorage.Delete(ctx, SidPrefix+sessionID)
				return p.secStorage.Set(ctx, sec_storage.RevokedSessionPrefix+sessionID, "blacklisted", ttl)
			}
			return nil
		})
	}

	// 2. Initialize handlers and mount routes if huma API is present
	refreshMaxAge := ictx.Config.Session.ExpiresIn
	if refreshMaxAge <= 0 {
		refreshMaxAge = 7 * 24 * time.Hour
	}
	cookieAttrs := humaaccesstoken.CookieAttrs{
		Secure:        ictx.Config.SecureCookies(),
		Domain:        ictx.Config.CookieDomain(),
		RefreshMaxAge: refreshMaxAge,
	}

	p.handler = humaaccesstoken.NewAccessTokenHandler(p.authSvc, p.sessionSvc, &sConf, cookieAttrs)

	p.authConfig = ictx.Config
	p.middleware = p.buildMiddleware(ictx.Config)

	if ictx.Api != nil {
		if p.config.AutoRegisterMiddleware {
			ictx.Api.UseMiddleware(p.middleware)
		}
		p.SetupHumaRoutes(ictx.Api, ictx.MiddleWare)
	}

	return nil
}

// RequireRefreshToken returns a Huma middleware that requires a valid session.token (Refresh Token)
// and explicitly rejects Access Token JWTs (3-segment tokens).
func (p *Plugin) RequireRefreshToken() func(ctx huma.Context, next func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		// 1. Check Authorization header for access token JWT
		authHeader := ctx.Header("Authorization")
		if authHeader == "" {
			authHeader = ctx.Header("authorization")
		}
		if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			raw := strings.TrimSpace(authHeader[7:])
			// A 3-segment token is an access token JWT, which is forbidden on refresh-token-only routes
			if strings.Count(raw, ".") == 2 {
				ctx.SetStatus(http.StatusUnauthorized)
				ctx.SetHeader("Content-Type", "application/json")
				_ = json.NewEncoder(ctx.BodyWriter()).Encode(map[string]any{
					"message": "access token not allowed on refresh-token-only route",
				})
				return
			}
		}
		// 2. Proceed to downstream handler
		next(ctx)
	}
}

// Middleware returns the exported Huma middleware for access-token authentication.
// When called with no arguments, it returns the middleware initialized during plugin Init.
// When called with an explicit AuthConfig, it builds and returns a new middleware instance.
func (p *Plugin) Middleware(authCfg ...config.AuthConfig) func(ctx huma.Context, next func(huma.Context)) {
	if len(authCfg) > 0 {
		return p.buildMiddleware(authCfg[0])
	}
	if p.middleware != nil {
		return p.middleware
	}
	return p.buildMiddleware(p.authConfig)
}

// AuthMiddleware returns the exported access-token Huma middleware for client applications to use on protected routes.
func (p *Plugin) AuthMiddleware() func(ctx huma.Context, next func(huma.Context)) {
	return p.Middleware()
}

// InitMiddleware explicitly initializes and returns an access-token middleware that client applications can use.
func (p *Plugin) InitMiddleware(authCfg ...config.AuthConfig) func(ctx huma.Context, next func(huma.Context)) {
	if len(authCfg) > 0 {
		p.authConfig = authCfg[0]
	}
	p.middleware = p.buildMiddleware(p.authConfig)
	return p.middleware
}

// HTTPMiddleware exports a standard net/http middleware (func(http.Handler) http.Handler) for client applications.
func (p *Plugin) HTTPMiddleware(authCfg ...config.AuthConfig) func(http.Handler) http.Handler {
	cfg := p.authConfig
	if len(authCfg) > 0 {
		cfg = authCfg[0]
	}
	accessSecret := p.sessionConf.JWT.AccessSecret
	if accessSecret == "" && cfg.Secret != "" {
		accessSecret = config.DeriveKey(cfg.Secret, "goauth-access")
	}
	if accessSecret == "" {
		accessSecret = cfg.Secret
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
				raw := strings.TrimSpace(authHeader[7:])
				if raw != "" && strings.Count(raw, ".") == 2 {
					claims, err := jwttoken.ValidateAccessToken(raw, accessSecret)
					if err == nil && claims != nil && claims.SessionID != "" {
						ctx := r.Context()
						ctx = context.WithValue(ctx, constant.CtxClaims.Str(), *claims)
						ctx = context.WithValue(ctx, constant.CTXUser_ID.Str(), claims.UserID)
						if claims.ActiveOrgId != "" {
							ctx = context.WithValue(ctx, constant.CTXCompany_ID.Str(), claims.ActiveOrgId)
						}
						r = r.WithContext(ctx)
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

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
				// 1. Verify access JWT
				claims, err := jwttoken.ValidateAccessToken(raw, accessSecret)
				if err == nil && claims != nil && claims.SessionID != "" {
					// Preserve original token org/team claims to detect session mutations after handler runs
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

						// Layer 2 fix: If this request mutates active org/role/team (e.g. SetActiveOrganization / SetActiveTeam),
						// mint a fresh access JWT and return it in the set-auth-token response header before writing headers.
						if p.sessionSvc != nil {
							sessionID := claims.SessionID
							innerCtx := ctx
							wrapped := &accessTokenContextWrapper{
								inner: innerCtx,
								onBeforeWrite: func() {
									latest, _ := p.resolveLiveSessionByID(innerCtx.Context(), sessionID, false)
									if latest == nil {
										return
									}
									curOrgID := derefStr(latest.Session.ActiveOrganizationID)
									curOrgRole := derefStr(latest.Session.ActiveOrganizationRole)
									curTeamID := derefStr(latest.Session.ActiveTeamID)
									if curOrgID == tokenOrgID && curOrgRole == tokenOrgRole && curTeamID == tokenTeamID {
										return
									}
									tokens, tokErr := p.sessionSvc.Tokens(&latest.Session, latest.User.Role)
									if tokErr != nil || tokens == nil || tokens.AccessToken == "" {
										return
									}
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

type accessTokenContextWrapper struct {
	inner         huma.Context
	onBeforeWrite func()
	wrote         bool
}

var _ huma.Context = (*accessTokenContextWrapper)(nil)

func (w *accessTokenContextWrapper) flush() {
	if !w.wrote {
		w.wrote = true
		if w.onBeforeWrite != nil {
			w.onBeforeWrite()
		}
	}
}

func (w *accessTokenContextWrapper) Unwrap() huma.Context       { return w.inner }
func (w *accessTokenContextWrapper) Operation() *huma.Operation { return w.inner.Operation() }
func (w *accessTokenContextWrapper) Context() context.Context   { return w.inner.Context() }
func (w *accessTokenContextWrapper) TLS() *tls.ConnectionState  { return w.inner.TLS() }
func (w *accessTokenContextWrapper) Version() huma.ProtoVersion { return w.inner.Version() }
func (w *accessTokenContextWrapper) Method() string             { return w.inner.Method() }
func (w *accessTokenContextWrapper) Host() string               { return w.inner.Host() }
func (w *accessTokenContextWrapper) RemoteAddr() string         { return w.inner.RemoteAddr() }
func (w *accessTokenContextWrapper) URL() url.URL               { return w.inner.URL() }
func (w *accessTokenContextWrapper) Param(name string) string   { return w.inner.Param(name) }
func (w *accessTokenContextWrapper) Query(name string) string   { return w.inner.Query(name) }
func (w *accessTokenContextWrapper) Header(name string) string  { return w.inner.Header(name) }
func (w *accessTokenContextWrapper) EachHeader(cb func(name, value string)) {
	w.inner.EachHeader(cb)
}
func (w *accessTokenContextWrapper) BodyReader() io.Reader { return w.inner.BodyReader() }
func (w *accessTokenContextWrapper) GetMultipartForm() (*multipart.Form, error) {
	return w.inner.GetMultipartForm()
}

func (w *accessTokenContextWrapper) SetReadDeadline(t time.Time) error {
	return w.inner.SetReadDeadline(t)
}
func (w *accessTokenContextWrapper) Status() int { return w.inner.Status() }
func (w *accessTokenContextWrapper) SetStatus(code int) {
	w.flush()
	w.inner.SetStatus(code)
}
func (w *accessTokenContextWrapper) SetHeader(name, value string) { w.inner.SetHeader(name, value) }
func (w *accessTokenContextWrapper) AppendHeader(name, value string) {
	w.inner.AppendHeader(name, value)
}

func (w *accessTokenContextWrapper) BodyWriter() io.Writer {
	w.flush()
	return w.inner.BodyWriter()
}

func appendExposedHeader(current, toAdd string) string {
	if current == "" {
		return toAdd
	}
	for _, p := range strings.Split(current, ",") {
		if strings.EqualFold(strings.TrimSpace(p), toAdd) {
			return current
		}
	}
	return current + ", " + toAdd
}

func injectCookieHeader(r *http.Request, cookieName, signedCookieVal string) {
	if cookieName == "" || signedCookieVal == "" {
		return
	}
	cookieStr := (&http.Cookie{Name: cookieName, Value: signedCookieVal, Path: "/"}).String()
	// cookieStr is "name=value; Path=/"; we only need "name=value" for request header
	if idx := len(cookieName) + 1 + len(signedCookieVal); idx < len(cookieStr) {
		cookieStr = cookieName + "=" + signedCookieVal
	}
	existingCookie := r.Header.Get("Cookie")
	if existingCookie == "" {
		r.Header.Set("Cookie", cookieStr)
	} else if !containsCookie(existingCookie, cookieName) {
		r.Header.Set("Cookie", existingCookie+"; "+cookieStr)
	}
}

func containsCookie(header, name string) bool {
	// minimal check; full parse not needed on hot path
	for _, part := range splitCookieHeader(header) {
		if part == name || len(part) > len(name) && part[:len(name)+1] == name+"=" {
			return true
		}
		// fallback: substring search for "name="
		_ = part
	}
	// Use substring as fallback (covers compact headers)
	return containsSubstr(header, name+"=")
}

func containsSubstr(s, sub string) bool { return len(s) >= len(sub) && indexOf(s, sub) >= 0 }
func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func splitCookieHeader(h string) []string {
	parts := []string{}
	start := 0
	for i := 0; i < len(h); i++ {
		if h[i] == ';' {
			parts = append(parts, trimSpace(h[start:i]))
			start = i + 1
		}
	}
	parts = append(parts, trimSpace(h[start:]))
	return parts
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '	') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '	') {
		s = s[:len(s)-1]
	}
	return s
}

// Migrator returns nil because access-token plugin uses core tables.
func (p *Plugin) Migrator() migration.IMigrator {
	return nil
}

// Services returns services exposed by this plugin.
func (p *Plugin) Services() map[string]any {
	return map[string]any{
		"access_token_auth":         p.authSvc,
		"access_token_session":      p.sessionSvc,
		"access_token_verification": p.vSvc,
		"access_token_middleware":   p.Middleware(),
	}
}

// Routes returns nil since routes are registered via SetupHumaRoutes.
func (p *Plugin) Routes() []plugins.RouteDescriptor {
	return nil
}

// SetupHumaRoutes registers the plugin routes onto a huma.API instance.
func (p *Plugin) SetupHumaRoutes(api huma.API, mdlware *middleware.AuthMiddleware) {
	if p.handler == nil {
		return
	}
	humaaccesstoken.SetupAccessTokenRoutes(api, p.handler, mdlware, p.basePath)
}

// AccessSecret returns the configured JWT access token signing secret, if any.
func (p *Plugin) AccessSecret() string {
	return p.sessionConf.JWT.AccessSecret
}

// Handler returns the initialized AccessTokenHandler.
func (p *Plugin) Handler() *humaaccesstoken.AccessTokenHandler {
	return p.handler
}

// AuthService returns the initialized AuthService.
func (p *Plugin) AuthService() *services.AuthService {
	return p.authSvc
}

// SessionService returns the initialized SessionService.
func (p *Plugin) SessionService() *services.SessionService {
	return p.sessionSvc
}

// VerificationService returns the initialized VerificationService.
func (p *Plugin) VerificationService() *services.VerificationService {
	return p.vSvc
}
