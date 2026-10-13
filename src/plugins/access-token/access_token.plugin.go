package accesstoken

import (
	"context"
	"fmt"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	authint "github.com/better-go-auth/goauth/src/app/services/interfaces"
	leg_int"github.com/better-go-auth/goauth/src/plugins/access-token/services/interfaces"

	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	"github.com/better-go-auth/goauth/src/common/middleware"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	humaaccesstoken "github.com/better-go-auth/goauth/src/plugins/access-token/adapters/huma"
	accesstokenconfig "github.com/better-go-auth/goauth/src/plugins/access-token/config"
	"github.com/better-go-auth/goauth/src/plugins/access-token/services"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
	"github.com/danielgtaylor/huma/v2"
	"gorm.io/gorm"
)

const PluginID = "access-token"

// Plugin implements plugins.Plugin for legacy access-token / JWT authentication.
type Plugin struct {
	config      accesstokenconfig.AccessTokenConfig
	basePath    string
	sessionConf config.SessionGoAuth
	//
	vConf       config.EmailVerification
	passwords   *authcrypto.Passwords

	authSvc    *services.AuthService
	sessionSvc *services.SessionService
	profileSvc *services.ProfileService
	vSvc       *services.VerificationService
	//
	handler    *humaaccesstoken.AccessTokenHandler

	repos      repo_interfaces.IAuthRepos
	sessionMgr authint.ISessionManager
	IAuthSvc   authint.IAuthService
	secStorage sec_storage.SecondaryStorage
	txMgr      interfaces.ITransactionManager
}

var _ plugins.Plugin = (*Plugin)(nil)

// Option configures the access-token Plugin.
type Option func(*Plugin)

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
func New(opts ...Option) *Plugin {
	p := &Plugin{
		config: accesstokenconfig.DefaultAccessTokenConfig(),
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
	if txMgr == nil {
		if dbVal, ok := ictx.Extras["db"].(*gorm.DB); ok && dbVal != nil {
			txMgr = gormutil.NewGormTxManager(dbVal)
		}
	}
	p.txMgr = txMgr
	

	p.sessionMgr = ictx.SessionManager

	// Resolve secondary storage
	secStorage := ictx.SecondaryStorage
	if secStorage == nil && ictx.Extras != nil {
		if ssVal, ok := ictx.Extras["secondaryStorage"].(sec_storage.SecondaryStorage); ok {
			secStorage = ssVal
		}
	}
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
	if sessMgr == nil && ictx.Extras != nil {
		if sm, ok := ictx.Extras["sessionManager"].(authint.ISessionManager); ok {
			sessMgr = sm
		}
	}
	coreAuthSvc:= ictx.IAuthSvc
	if coreAuthSvc == nil {
		return fmt.Errorf("access-token plugin: IAuthSvc is required")
	}
	p.IAuthSvc = coreAuthSvc
	//initialize the legacy services
	p.vSvc = services.NewVerificationService(repos, vConf)
	p.sessionSvc = services.NewSessionService(sConf, repos, sessMgr, secStorage, ictx.Hooks)
	p.authSvc = services.NewAuthService(&sConf, coreAuthSvc,p.vSvc, p.sessionSvc, repos, txMgr, p.passwords, ictx.Hooks)
	p.profileSvc = services.NewProfileService(p.vSvc, p.sessionSvc, repos, txMgr, p.passwords)

	// TODO: is this how other plugins do it
	// Register lifecycle hook to terminate legacy sessions when a user is banned
	if ictx.Hooks != nil {
		ictx.Hooks.OnUserBanned(func(ctx context.Context, userID string, reason *string) error {
			return p.sessionSvc.DeleteAllUserSessions(ctx, userID)
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
		ProfileServ: p.profileSvc,
		SessionRepo: repos,
		Config:      &sConf,
		Cookies:     cookieAttrs,
	}

	if ictx.Api != nil {
		p.SetupHumaRoutes(ictx.Api, ictx.MiddleWare)
	}

	return nil
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
		"access_token_profile":      p.profileSvc,
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
func (p *Plugin) ProfileService() *services.ProfileService {
	return p.profileSvc
}

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
