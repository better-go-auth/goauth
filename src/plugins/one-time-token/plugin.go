// Package onetimetoken ports better-auth's one-time-token plugin: GET /one-time-token/generate creates a
// short-lived single-use token for the current session, POST /one-time-token/verify exchanges it for the
// session (and its cookie).
//
// Tokens live in the verification table under "one-time-token:<token>" (or its hash), so the plugin has no
// migrator. With SetOttHeaderOnNewSession the plugin adds a `set-ott` header to every response that sets a
// new session cookie, through a Huma API middleware (pluginkit.UseAfterHook). goauth.New initializes this
// plugin before the other domain plugins, so the middleware covers the core routes and every plugin route.
package onetimetoken

import (
	"errors"
	"time"

	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	humaott "github.com/better-go-auth/goauth/src/plugins/one-time-token/adapters/huma"
	"github.com/better-go-auth/goauth/src/plugins/one-time-token/config"
	"github.com/better-go-auth/goauth/src/plugins/one-time-token/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

// PluginID is better-auth's plugin id.
const PluginID = "one-time-token"

// Plugin implements plugins.Plugin for better-auth's one-time-token plugin.
type Plugin struct {
	config  config.OneTimeTokenConfig
	kit     *pluginkit.Kit
	service *services.OneTimeTokenService
	handler *humaott.Handler
}

var _ plugins.Plugin = (*Plugin)(nil)

// Option configures the plugin.
type Option func(*Plugin)

// WithExpiresIn sets the token lifetime (default 3 minutes).
func WithExpiresIn(d time.Duration) Option {
	return func(p *Plugin) { p.config.ExpiresIn = d }
}

// WithDisableClientRequest rejects token generation over HTTP.
func WithDisableClientRequest(disable bool) Option {
	return func(p *Plugin) { p.config.DisableClientRequest = disable }
}

// WithDisableSetSessionCookie stops verify from setting the session cookie.
func WithDisableSetSessionCookie(disable bool) Option {
	return func(p *Plugin) { p.config.DisableSetSessionCookie = disable }
}

// WithGenerateToken replaces the random token generator.
func WithGenerateToken(fn config.GenerateTokenFunc) Option {
	return func(p *Plugin) { p.config.GenerateToken = fn }
}

// WithStoreToken selects how tokens are stored.
func WithStoreToken(st config.StoreTokenConfig) Option {
	return func(p *Plugin) { p.config.StoreToken = st }
}

// WithSetOttHeaderOnNewSession adds the `set-ott` header to responses that create a session.
func WithSetOttHeaderOnNewSession(enable bool) Option {
	return func(p *Plugin) { p.config.SetOttHeaderOnNewSession = enable }
}

// New creates the one-time-token plugin.
func New(cfg config.OneTimeTokenConfig, opts ...Option) *Plugin {
	p := &Plugin{config: cfg}
	for _, opt := range opts {
		opt(p)
	}
	p.config = p.config.WithDefaults()
	return p
}

// ID returns "one-time-token".
func (p *Plugin) ID() string { return PluginID }

// Init builds the service, registers the after hook and mounts the endpoints.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	if ictx == nil {
		return errors.New("one-time-token: init context is required")
	}
	// Step 1: shared plugin runtime (sessions, cookies, origin check)
	kit, err := pluginkit.New(ictx)
	if err != nil {
		return err
	}
	p.kit = kit
	// Step 2: service and HTTP handler
	p.service = services.NewOneTimeTokenService(p.config, kit)
	p.handler = humaott.NewHandler(p.service)
	// Step 3: the set-ott after hook (only registered when enabled)
	if p.config.SetOttHeaderOnNewSession {
		kit.UseAfterHook(ictx.Api, nil, p.service.AfterHook)
	}
	// Step 4: mount the routes
	humaott.RegisterRoutes(ictx.Api, kit, p.handler)
	return nil
}

// Migrator returns nil: tokens are stored in the core verification table.
func (p *Plugin) Migrator() migration.IMigrator { return nil }

// Services exposes the plugin service.
func (p *Plugin) Services() map[string]any {
	return map[string]any{"oneTimeToken": p.service}
}

// Routes returns nil: routes are mounted on Huma in Init.
func (p *Plugin) Routes() []plugins.RouteDescriptor { return nil }

// Service returns the plugin service (nil before Init).
func (p *Plugin) Service() *services.OneTimeTokenService { return p.service }

// Config returns the effective configuration.
func (p *Plugin) Config() config.OneTimeTokenConfig { return p.config }
