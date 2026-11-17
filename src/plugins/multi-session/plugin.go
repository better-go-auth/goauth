// Package multisession ports better-auth's multi-session plugin: a browser can hold sessions of several
// users at once (one signed `<session_token>_multi-<token>` cookie per session), list them, switch the active
// one and revoke them.
//
// The plugin keeps better-auth's after-hook semantics with a Huma API middleware (pluginkit.UseAfterHook):
// every response that sets a new session cookie gets a multi-session cookie, and /sign-out revokes every
// device session. goauth.New initializes this plugin before the other domain plugins, so the middleware wraps
// the core routes and every plugin route whatever the order of GoAuthOptions.Plugins.
//
// The plugin has no tables, so it has no migrator.
package multisession

import (
	"errors"

	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	humamulti "github.com/better-go-auth/goauth/src/plugins/multi-session/adapters/huma"
	"github.com/better-go-auth/goauth/src/plugins/multi-session/config"
	"github.com/better-go-auth/goauth/src/plugins/multi-session/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

// PluginID is better-auth's plugin id.
const PluginID = "multi-session"

// ErrorCodes are better-auth's MULTI_SESSION_ERROR_CODES.
var ErrorCodes = services.ErrorCodes

// Plugin implements plugins.Plugin for better-auth's multi-session plugin.
type Plugin struct {
	config  config.MultiSessionConfig
	kit     *pluginkit.Kit
	service *services.MultiSessionService
	handler *humamulti.Handler
}

var _ plugins.Plugin = (*Plugin)(nil)

// Option configures the plugin.
type Option func(*Plugin)

// WithMaximumSessions sets the maximum number of sessions per device (default 5).
func WithMaximumSessions(n int) Option {
	return func(p *Plugin) { p.config.MaximumSessions = n }
}

// New creates the multi-session plugin.
func New(cfg config.MultiSessionConfig, opts ...Option) *Plugin {
	p := &Plugin{config: cfg}
	for _, opt := range opts {
		opt(p)
	}
	p.config = p.config.WithDefaults()
	return p
}

// ID returns "multi-session".
func (p *Plugin) ID() string { return PluginID }

// Init builds the service, registers the after hook and mounts the endpoints.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	if ictx == nil {
		return errors.New("multi-session: init context is required")
	}
	// Step 1: shared plugin runtime (sessions, cookies, origin check)
	kit, err := pluginkit.New(ictx)
	if err != nil {
		return err
	}
	p.kit = kit
	// Step 2: service and HTTP handler
	p.service = services.NewMultiSessionService(p.config, kit)
	p.handler = humamulti.NewHandler(p.service)
	// Step 3: the after hook must be registered before any route it should observe is mounted
	kit.UseAfterHook(ictx.Api, nil, p.service.AfterHook)
	// Step 4: mount the routes
	humamulti.RegisterRoutes(ictx.Api, kit, p.handler)
	return nil
}

// Migrator returns nil: the plugin has no tables.
func (p *Plugin) Migrator() migration.IMigrator { return nil }

// Services exposes the plugin service.
func (p *Plugin) Services() map[string]any {
	return map[string]any{"multiSession": p.service}
}

// Routes returns nil: routes are mounted on Huma in Init.
func (p *Plugin) Routes() []plugins.RouteDescriptor { return nil }

// Service returns the plugin service (nil before Init).
func (p *Plugin) Service() *services.MultiSessionService { return p.service }

// Config returns the effective configuration.
func (p *Plugin) Config() config.MultiSessionConfig { return p.config }
