package accesstoken

import (
	"context"
	"net/http"
	"fmt"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	authint "github.com/better-go-auth/goauth/src/app/services/interfaces"
	leg_int "github.com/better-go-auth/goauth/src/plugins/access-token/services/interfaces"

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
	jwttoken "github.com/better-go-auth/goauth/src/providers/token/jwt-token"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
)

const PluginID = "access-token"

// Plugin implements plugins.Plugin for legacy access-token / JWT authentication.
type Plugin struct {
	config      accesstokenconfig.AccessTokenConfig
	basePath    string
	sessionConf config.SessionGoAuth
	//
	vConf     config.EmailVerification
	passwords *authcrypto.Passwords

	authSvc    *services.AuthService
	sessionSvc *services.SessionService
	// profileSvc *services.ProfileService
	vSvc *services.VerificationService
	//
	handler *humaaccesstoken.AccessTokenHandler

	repos      repo_interfaces.IAuthRepos
	sessionMgr authint.ISessionManager
	IAuthSvc   authint.IAuthService
	secStorage sec_storage.SecondaryStorage
	txMgr      interfaces.ITransactionManager
}

var _ plugins.Plugin = (*Plugin)(nil)

// Option configures the access-token Plugin.
type Option func(*Plugin)

// WithConfig sets the entire AccessTokenConfig.
func WithConfig(conf accesstokenconfig.AccessTokenConfig) Option {
	return func(p *Plugin) {
		p.config = conf
		p.sessionConf = conf.Session
		p.vConf = conf.Verification
	}
}

// WithBasePath sets custom base path (e.g. "/api/auth").
func WithBasePath(basePath string) Option {
	return func(p *Plugin) {
		p.basePath = basePath
	}
}

// WithSessionConfig sets session settings for JWT.
func WithSessionConfig(conf config.SessionGoAuth) Option {
	return func(p *Plugin) {
		p.sessionConf = conf
		p.config.Session = conf
	}
}

// WithVerificationConfig sets email verification configuration.
func WithVerificationConfig(conf config.EmailVerification) Option {
	return func(p *Plugin) {
		p.vConf = conf
		p.config.Verification = conf
	}
}

// WithPasswords sets a pre-configured Passwords hasher.
func WithPasswords(passwords *authcrypto.Passwords) Option {
	return func(p *Plugin) {
		p.passwords = passwords
	}
}

// New creates a new access-token Plugin.
// Directly accepts the config struct so users can configure it directly (mimicking Better Auth's plugin pattern),
// with functional options supported as additional optional overrides.
func New(cfg accesstokenconfig.AccessTokenConfig, opts ...Option) *Plugin {
	defaultCfg := accesstokenconfig.DefaultAccessTokenConfig()
	if cfg.BasePath == "" {
		cfg.BasePath = defaultCfg.BasePath
	}
	if cfg.Session.JWT.AccessExpiresIn <= 0 {
		cfg.Session.JWT.AccessExpiresIn = defaultCfg.Session.JWT.AccessExpiresIn
	}
	if cfg.Session.JWT.RefreshExpiresIn <= 0 {
		cfg.Session.JWT.RefreshExpiresIn = defaultCfg.Session.JWT.RefreshExpiresIn
	}
	if cfg.Verification.GoAuth.CodeExpiresIn <= 0 {
		cfg.Verification.GoAuth.CodeExpiresIn = defaultCfg.Verification.GoAuth.CodeExpiresIn
	}

	p := &Plugin{
		config:      cfg,
		sessionConf: cfg.Session,
		vConf:       cfg.Verification,
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
	if sConf.JWT.AccessSecret == "" {
		sConf = ictx.Config.GoAuth.Session
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
	p.authSvc = services.NewAuthService(&sConf, coreAuthSvc, p.vSvc, p.sessionSvc, repos, txMgr, p.passwords, ictx.Hooks)
	// p.profileSvc = services.NewProfileService(p.vSvc, p.sessionSvc, repos, txMgr, p.passwords)

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
		refreshMaxAge = sConf.JWT.RefreshExpiresIn
	}
	cookieAttrs := humaaccesstoken.CookieAttrs{
		Secure:        ictx.Config.SecureCookies(),
		Domain:        ictx.Config.CookieDomain(),
		RefreshMaxAge: refreshMaxAge,
	}

	p.handler = &humaaccesstoken.AccessTokenHandler{
		AuthServ:    p.authSvc,
		SessionServ: p.sessionSvc,
		// ProfileServ: p.profileSvc,
		SessionRepo: repos,
		Config:      &sConf,
		Cookies:     cookieAttrs,
	}

	if ictx.Api != nil {
		ictx.Api.UseMiddleware(p.Middleware(ictx.Config))
		p.SetupHumaRoutes(ictx.Api, ictx.MiddleWare)
	}

	return nil
}

// Middleware creates Huma middleware that authenticates incoming Authorization: Bearer <access_token_jwt> headers.
// It verifies the access token, resolves the user and session, populates them into the request context,
// and injects the session cookie so that all standard Better Auth endpoints work seamlessly without custom profile endpoints.
func (p *Plugin) Middleware(authCfg config.AuthConfig) func(ctx huma.Context, next func(huma.Context)) {
	cm := cookies.New(authCfg)
	cookieName := cm.Name(cookies.CookieSessionToken)
	accessSecret := p.sessionConf.JWT.AccessSecret
	if accessSecret == "" {
		accessSecret = authCfg.GoAuth.Session.JWT.AccessSecret
	}
	if accessSecret == "" {
		accessSecret = authCfg.Secret
	}

	return func(ctx huma.Context, next func(huma.Context)) {
		authHeader := ctx.Header("Authorization")
		if authHeader == "" {
			authHeader = ctx.Header("authorization")
		}

		if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			raw := strings.TrimSpace(authHeader[7:])
			if raw != "" && strings.Count(raw, ".") == 2 {
				// 1. Verify access JWT
				claims, err := jwttoken.ValidateAccessToken(raw, accessSecret)
				if err == nil && claims != nil && claims.SessionID != "" {
					// 2. Revocation check — check if session is blacklisted in secondary storage.
					isRevoked := false
					if p.secStorage != nil {
						if _, exists, _ := p.secStorage.Get(ctx.Context(), sec_storage.RevokedSessionPrefix+claims.SessionID); exists {
					isRevoked = true
				}
					}
					// 3. Fast-path: plugin-owned sid: -> token index (zero DB hit when cache warm)
					var sw *dtos.SessionWithUser
					var sessToken string
					if !isRevoked && p.sessionSvc != nil {
						if cached, _ := p.sessionSvc.GetBySID(ctx.Context(), claims.SessionID); cached != nil {
							sw = cached
							sessToken = cached.Session.Token
						}
					}
					// 4. DB fallback on index miss + backfill
					if sw == nil && !isRevoked && p.repos != nil {
						sess, err := p.repos.FindSessionByID(ctx.Context(), claims.SessionID)
						if err == nil && sess != nil && sess.ExpiresAt.After(time.Now()) {
							if p.sessionMgr != nil {
								sw, _ = p.sessionMgr.Get(ctx.Context(), sess.Token)
							}
							if sw == nil {
								u, err := p.repos.FindUserByID(ctx.Context(), sess.UserID)
								if err == nil && u != nil {
									sw = &dtos.SessionWithUser{
										Session: dtos.SessionFromModel(sess),
										User:    dtos.UserFromModel(u),
									}
								}
							}
							if sw != nil {
								sessToken = sess.Token
								ttl := time.Until(sess.ExpiresAt)
								if ttl > 0 {
									if p.sessionSvc != nil {
										p.sessionSvc.BackfillSidIndex(ctx.Context(), sess.ID, sess.Token, ttl)
									} else if p.secStorage != nil {
										_ = p.secStorage.Set(ctx.Context(), SidPrefix+sess.ID, sess.Token, ttl)
									}
								}
							}
						}
					}

					if sw != nil {
						tok := sessToken
						if tok == "" {
							tok = sw.Session.Token
						}
						// Attach to context
						ctx = huma.WithContext(ctx, humaadapter.WithSession(ctx.Context(), sw))
						ctx = huma.WithContext(ctx, humaadapter.WithBearerToken(ctx.Context(), tok))
						ctx = huma.WithValue(ctx, constant.CtxClaims.Str(), *claims)
						ctx = huma.WithValue(ctx, constant.CTXUser_ID.Str(), claims.UserID)
						if claims.ActiveOrgId != "" {
							ctx = huma.WithValue(ctx, constant.CTXCompany_ID.Str(), claims.ActiveOrgId)
						}

						if !idgen.IsToken(tok) {
							tok = ""
						} else {
							signedCookieVal := cm.Signed(tok)
							if r, _ := humago.Unwrap(ctx); r != nil {
								injectCookieHeader(r, cookieName, signedCookieVal)
							}
						}
					}
				}
			} else if raw != "" && p.sessionMgr != nil {
				if sw, _ := p.sessionMgr.Get(ctx.Context(), raw); sw != nil {
					// Attach to context
					ctx = huma.WithContext(ctx, humaadapter.WithSession(ctx.Context(), sw))
					ctx = huma.WithContext(ctx, humaadapter.WithBearerToken(ctx.Context(), raw))
					ctx = huma.WithValue(ctx, constant.CTXUser_ID.Str(), sw.User.ID)
					if sw.Session.ActiveOrganizationID != nil {
						ctx = huma.WithValue(ctx, constant.CTXCompany_ID.Str(), *sw.Session.ActiveOrganizationID)
					}

					if idgen.IsToken(raw) {
						signedCookieVal := cm.Signed(raw)
						if r, _ := humago.Unwrap(ctx); r != nil {
							injectCookieHeader(r, cookieName, signedCookieVal)
						}
					}
				}
			}
		}

		next(ctx)
	}
}

// Migrator returns nil because access-token plugin uses core tables.

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
func indexOf(s, sub string) int { for i := 0; i <= len(s)-len(sub); i++ { if s[i:i+len(sub)] == sub { return i } }; return -1 }
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
	for len(s) > 0 && (s[0] == ' ' || s[0] == '	') { s = s[1:] }
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '	') { s = s[:len(s)-1] }
	return s
}

func (p *Plugin) Migrator() migration.IMigrator {
	return nil
}

// Services returns services exposed by this plugin.
func (p *Plugin) Services() map[string]any {
	return map[string]any{
		"access_token_auth":    p.authSvc,
		"access_token_session": p.sessionSvc,
		// "access_token_profile":      p.profileSvc,
		"access_token_verification": p.vSvc,
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

// ProfileService returns the initialized ProfileService.
// func (p *Plugin) ProfileService() *services.ProfileService {
// 	return p.profileSvc
// }

// VerificationService returns the initialized VerificationService.
func (p *Plugin) VerificationService() *services.VerificationService {
	return p.vSvc
}

// LegacyAuthServices returns the combined ILegacyAuthServices implementation.
func (p *Plugin) LegacyAuthServices() leg_int.ILegacyAuthServices {
	if p.vSvc == nil && p.sessionSvc == nil {
		return nil
	}
	return leg_int.LegacyAuthServiceImpl{
		IVerificationService: p.vSvc,
		LegacySessionService: p.sessionSvc,
	}
}
