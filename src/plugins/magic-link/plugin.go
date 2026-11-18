// Package magiclink is better-auth's magic-link plugin: passwordless sign-in through a one-time link
// (POST /sign-in/magic-link, GET /magic-link/verify).
package magiclink

import (
	"errors"
	"time"

	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	humamagiclink "github.com/better-go-auth/goauth/src/plugins/magic-link/adapters/huma"
	magiclinkconfig "github.com/better-go-auth/goauth/src/plugins/magic-link/config"
	"github.com/better-go-auth/goauth/src/plugins/magic-link/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/providers/ratelimit"
)

// PluginID is better-auth's plugin id.
const PluginID = "magic-link"

// Plugin implements plugins.Plugin for better-auth's magic link.
type Plugin struct {
	config  magiclinkconfig.MagicLinkConfig
	kit     *pluginkit.Kit
	service *services.MagicLinkService
	handler *humamagiclink.MagicLinkHandler
}

var (
	_ plugins.Plugin            = (*Plugin)(nil)
	_ plugins.RateLimitProvider = (*Plugin)(nil)
)

// Option configures the plugin on top of the config struct.
type Option func(*Plugin)

// WithSendMagicLink sets the callback that delivers the link.
func WithSendMagicLink(fn magiclinkconfig.SendMagicLink) Option {
	return func(p *Plugin) { p.config.SendMagicLink = fn }
}

// WithExpiresIn sets how long links stay valid (default 5 minutes).
func WithExpiresIn(d time.Duration) Option {
	return func(p *Plugin) { p.config.ExpiresIn = d }
}

// WithDisableSignUp stops verify from creating new users.
func WithDisableSignUp(disable bool) Option {
	return func(p *Plugin) { p.config.DisableSignUp = disable }
}

// WithGenerateToken sets a custom token generator.
func WithGenerateToken(fn magiclinkconfig.GenerateToken) Option {
	return func(p *Plugin) { p.config.GenerateToken = fn }
}

// WithStoreToken selects how tokens are stored (plain, hashed or custom hasher).
func WithStoreToken(st magiclinkconfig.StoreTokenConfig) Option {
	return func(p *Plugin) { p.config.StoreToken = st }
}

// WithRateLimit sets the rate limit rule of both endpoints (default 5 requests per 60s).
func WithRateLimit(window time.Duration, max int) Option {
	return func(p *Plugin) { p.config.RateLimit = magiclinkconfig.RateLimitConfig{Window: window, Max: max} }
}

// New creates the magic-link plugin. cfg.SendMagicLink is required.
func New(cfg magiclinkconfig.MagicLinkConfig, opts ...Option) *Plugin {
	// Step 1: apply the functional options
	p := &Plugin{config: cfg}
	for _, opt := range opts {
		opt(p)
	}
	// Step 2: fill better-auth's defaults for unset fields
	def := magiclinkconfig.DefaultConfig()
	if p.config.ExpiresIn <= 0 {
		p.config.ExpiresIn = def.ExpiresIn
	}
	if p.config.StoreToken.Mode == "" {
		if p.config.StoreToken.Hash != nil {
			p.config.StoreToken.Mode = magiclinkconfig.StoreTokenCustom
		} else {
			p.config.StoreToken.Mode = def.StoreToken.Mode
		}
	}
	if p.config.RateLimit.Window <= 0 {
		p.config.RateLimit.Window = def.RateLimit.Window
	}
	if p.config.RateLimit.Max <= 0 {
		p.config.RateLimit.Max = def.RateLimit.Max
	}
	return p
}

// ID returns "magic-link".
func (p *Plugin) ID() string { return PluginID }

// Init builds the service and mounts the endpoints.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	// Step 1: validate the configuration
	if p.config.SendMagicLink == nil {
		return errors.New("magic-link plugin: SendMagicLink is required")
	}
	if p.config.StoreToken.Mode == magiclinkconfig.StoreTokenCustom && p.config.StoreToken.Hash == nil {
		return errors.New("magic-link plugin: StoreToken.Hash is required with the custom-hasher mode")
	}

	// Step 2: build the shared plugin runtime
	kit, err := pluginkit.New(ictx)
	if err != nil {
		return err
	}
	p.kit = kit

	// Step 3: build the service and handler
	p.service = services.NewMagicLinkService(p.config, kit)
	p.handler = humamagiclink.NewMagicLinkHandler(p.service, kit)

	// Step 4: mount the routes (the plugin's rate limit rule is declared through RateLimitRules)
	humamagiclink.SetupMagicLinkRoutes(ictx.Api, kit, p.handler)
	return nil
}

// RateLimitRules is better-auth's magic-link rule: /sign-in/magic-link and /magic-link/verify get
// RateLimit.Window / Max (default 5 requests per 60 s) while the global limiter is enabled.
func (p *Plugin) RateLimitRules() []ratelimit.PathRule {
	return humamagiclink.RateLimitRules(ratelimit.Rule{Window: p.config.RateLimit.Window, Max: p.config.RateLimit.Max})
}

// Migrator returns nil: magic links use the core verification and user tables.
func (p *Plugin) Migrator() migration.IMigrator { return nil }

// Services exposes the magic-link service.
func (p *Plugin) Services() map[string]any {
	return map[string]any{"magic_link": p.service}
}

// Routes returns nil: the endpoints are mounted on the Huma API in Init.
func (p *Plugin) Routes() []plugins.RouteDescriptor { return nil }

// Service returns the initialized service.
func (p *Plugin) Service() *services.MagicLinkService { return p.service }

// Config returns the effective configuration.
func (p *Plugin) Config() magiclinkconfig.MagicLinkConfig { return p.config }
