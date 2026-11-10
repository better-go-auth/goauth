package emailotp

import (
	"context"
	"fmt"
	"time"

	"github.com/better-go-auth/goauth/src/common/middleware"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	humaemailotp "github.com/better-go-auth/goauth/src/plugins/email-otp/adapters/huma"
	emailotpconfig "github.com/better-go-auth/goauth/src/plugins/email-otp/config"
	"github.com/better-go-auth/goauth/src/plugins/email-otp/services"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	"github.com/danielgtaylor/huma/v2"
)

const PluginID = "email-otp"

// Plugin implements plugins.Plugin and plugins.HookProvider for Better Auth's Email OTP.
type Plugin struct {
	config      emailotpconfig.EmailOTPConfig
	basePath    string
	service     *services.EmailOTPService
	handler     *humaemailotp.EmailOTPHandler
	hookService *emailOTPHookService
	middleware  *middleware.AuthMiddleware
}

var (
	_ plugins.Plugin       = (*Plugin)(nil)
	_ plugins.HookProvider = (*Plugin)(nil)
)

// Option configures the Email OTP Plugin.
type Option func(*Plugin)

// WithConfig sets the entire EmailOTPConfig.
func WithConfig(cfg emailotpconfig.EmailOTPConfig) Option {
	return func(p *Plugin) {
		p.config = cfg
	}
}

// WithOtpLength sets the length of the OTP digits (default 6).
func WithOtpLength(length int) Option {
	return func(p *Plugin) {
		p.config.OtpLength = length
	}
}

// WithExpiresIn sets how long the OTP is valid for (default 5 minutes).
func WithExpiresIn(d time.Duration) Option {
	return func(p *Plugin) {
		p.config.ExpiresIn = d
	}
}

// WithSendVerificationOTP sets the callback that emails the OTP code to the user.
func WithSendVerificationOTP(fn emailotpconfig.SendVerificationOTP) Option {
	return func(p *Plugin) {
		p.config.SendVerificationOTP = fn
	}
}

// WithGenerateOTP sets a custom function to generate OTP codes.
func WithGenerateOTP(fn emailotpconfig.GenerateOTPFunc) Option {
	return func(p *Plugin) {
		p.config.GenerateOTP = fn
	}
}

// WithAllowedAttempts sets the maximum verification attempts allowed per OTP (default 3).
func WithAllowedAttempts(attempts int) Option {
	return func(p *Plugin) {
		p.config.AllowedAttempts = attempts
	}
}

// WithStoreOTP configures how OTP values are stored in the verification table.
func WithStoreOTP(storeCfg emailotpconfig.StoreOTPConfig) Option {
	return func(p *Plugin) {
		p.config.StoreOTP = storeCfg
	}
}

// WithResendStrategy configures how requesting a new OTP handles an existing valid OTP ("rotate" or "reuse").
func WithResendStrategy(strategy emailotpconfig.ResendStrategy) Option {
	return func(p *Plugin) {
		p.config.ResendStrategy = strategy
	}
}

// WithRateLimit configures rate limiting for Email OTP endpoints.
func WithRateLimit(window time.Duration, max int) Option {
	return func(p *Plugin) {
		enabled := true
		p.config.RateLimit = emailotpconfig.EmailOTPRateLimitConfig{
			Enabled: &enabled,
			Window:  window,
			Max:     max,
		}
	}
}

// WithOverrideDefaultEmailVerification sets whether OTP overrides standard link verification.
func WithOverrideDefaultEmailVerification(override bool) Option {
	return func(p *Plugin) {
		p.config.OverrideDefaultEmailVerification = override
	}
}

// WithSendVerificationOnSignUp sets whether to auto-send an OTP code right after user sign-up.
func WithSendVerificationOnSignUp(send bool) Option {
	return func(p *Plugin) {
		p.config.SendVerificationOnSignUp = send
	}
}

// WithDisableSignUp disables passwordless auto-registration when signing in with OTP.
func WithDisableSignUp(disable bool) Option {
	return func(p *Plugin) {
		p.config.DisableSignUp = disable
	}
}

// WithChangeEmail configures whether email change via OTP is enabled and if current email requires verification.
func WithChangeEmail(enabled bool, verifyCurrentEmail bool) Option {
	return func(p *Plugin) {
		p.config.ChangeEmail.Enabled = enabled
		p.config.ChangeEmail.VerifyCurrentEmail = verifyCurrentEmail
	}
}

// WithBasePath configures custom base path (e.g. "/api/auth").
func WithBasePath(basePath string) Option {
	return func(p *Plugin) {
		p.basePath = basePath
	}
}

// New creates a new Email OTP plugin instance.
// Directly accepts the config struct so users can configure it directly (mimicking Better Auth's plugin pattern),
// with functional options supported as additional optional overrides.
func New(cfg emailotpconfig.EmailOTPConfig, opts ...Option) *Plugin {
	// Step 1: Apply default values for unset fields matching Better Auth specifications
	defaultCfg := emailotpconfig.DefaultConfig()
	if cfg.OtpLength <= 0 {
		cfg.OtpLength = defaultCfg.OtpLength
	}
	if cfg.ExpiresIn <= 0 {
		cfg.ExpiresIn = defaultCfg.ExpiresIn
	}
	if cfg.AllowedAttempts <= 0 {
		cfg.AllowedAttempts = defaultCfg.AllowedAttempts
	}
	if cfg.StoreOTP.Mode == "" && cfg.StoreOTP.Hash == nil && cfg.StoreOTP.Encrypt == nil {
		cfg.StoreOTP.Mode = defaultCfg.StoreOTP.Mode
	}
	if cfg.ResendStrategy == "" {
		cfg.ResendStrategy = defaultCfg.ResendStrategy
	}

	// Step 2: Construct plugin and apply any functional options
	p := &Plugin{
		config: cfg,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// ID returns the unique identifier for this plugin.
func (p *Plugin) ID() string {
	return PluginID
}

// Init initializes the service, lifecycle hooks, and mounts Huma routes.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	// Step 1: Validate required dependencies in InitContext
	if ictx == nil {
		return fmt.Errorf("email-otp plugin: init context is required")
	}
	if ictx.IAuthRepos == nil {
		return fmt.Errorf("email-otp plugin: repositories are required")
	}

	// Step 2: Resolve base path
	if p.basePath == "" {
		p.basePath = ictx.Config.BasePath
	}
	if p.basePath == "" {
		p.basePath = "/api/auth"
	}

	// Step 3: Initialize EmailOTPService and attach secondary storage for rate limiting
	passwords := authcrypto.NewPasswords(ictx.Config)

	p.service = services.NewEmailOTPService(
		p.config,
		ictx.Config,
		ictx.IAuthRepos,
		ictx.SessionManager,
		passwords,
		ictx.TxManager,
	)
	if ictx.SecondaryStorage != nil {
		p.service.SetSecondaryStorage(ictx.SecondaryStorage)
	}

	// Step 4: Register lifecycle hook and global verification override sender when enabled
	p.hookService = &emailOTPHookService{plugin: p}
	if ictx.Hooks != nil {
		ictx.Hooks.Register(p.hookService)
		if p.config.OverrideDefaultEmailVerification {
			ictx.Hooks.SetVerificationEmailSender(func(ctx context.Context, user *models.User, _ string) error {
				if user == nil {
					return nil
				}
				return p.service.SendSignUpVerificationOTP(ctx, user.Email, config.GetHTTPRequest(ctx))
			})
		}
	}

	// Step 5: Construct HTTP handler and mount Huma routes
	cookieMgr := cookies.New(ictx.Config)
	p.middleware = ictx.MiddleWare
	p.handler = humaemailotp.NewEmailOTPHandler(p.service, cookieMgr, ictx.Config, ictx.Authenticator)

	if ictx.Api != nil {
		p.SetupHumaRoutes(ictx.Api)
	}

	return nil
}

// SetupHumaRoutes mounts the plugin endpoints on the provided Huma API.
func (p *Plugin) SetupHumaRoutes(api huma.API) {
	if p.handler == nil {
		return
	}
	humaemailotp.SetupEmailOTPRoutes(api, p.handler, p.basePath, p.middleware)
}

// Migrator returns nil since Email OTP uses the standard Better Auth verification and user tables.
func (p *Plugin) Migrator() migration.IMigrator {
	return nil
}

// Services exposes the email-otp service.
func (p *Plugin) Services() map[string]any {
	return map[string]any{
		"email_otp": p.service,
	}
}

// Routes returns nil since endpoints are mounted via SetupHumaRoutes.
func (p *Plugin) Routes() []plugins.RouteDescriptor {
	return nil
}

// Hooks returns the HookService for registering lifecycle events.
func (p *Plugin) Hooks() plugins.HookService {
	return p.hookService
}

// Service returns the initialized EmailOTPService.
func (p *Plugin) Service() *services.EmailOTPService {
	return p.service
}

// Handler returns the initialized EmailOTPHandler.
func (p *Plugin) Handler() *humaemailotp.EmailOTPHandler {
	return p.handler
}

// ─── Lifecycle Hook Implementation ─────────────────────────────────────────────

type emailOTPHookService struct {
	plugins.DefaultHookService
	plugin *Plugin
}

// AfterUserCreate runs right after an account is created in core SignUpEmail.
func (h *emailOTPHookService) AfterUserCreate(ctx context.Context, user *models.User) error {
	cfg := h.plugin.config
	// When sendVerificationOnSignUp or overrideDefaultEmailVerification is active, dispatch OTP
	if (cfg.SendVerificationOnSignUp || cfg.OverrideDefaultEmailVerification) && !user.EmailVerified {
		return h.plugin.service.SendSignUpVerificationOTP(ctx, user.Email, nil)
	}
	return nil
}
