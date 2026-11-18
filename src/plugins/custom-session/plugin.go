// Package customsession ports better-auth's custom-session plugin: the body of GET /get-session is replaced
// by the value a callback returns for the current session (e.g. the session plus the user's roles), and with
// ShouldMutateListDeviceSessionsEndpoint every entry of GET /multi-session/list-device-sessions too.
//
// better-auth replaces the core getSession endpoint; goauth keeps the core endpoint (cookie cache, session
// refresh, bearer tokens, cookies and headers all stay the same) and rewrites its JSON body in an after hook
// (plugins.EndpointHooksProvider). No session stays null. The plugin has no routes and no tables.
package customsession

import (
	"errors"

	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/custom-session/config"
	"github.com/better-go-auth/goauth/src/plugins/custom-session/services"
)

// PluginID is better-auth's plugin id.
const PluginID = "custom-session"

// Plugin implements plugins.Plugin and plugins.EndpointHooksProvider for better-auth's custom-session plugin.
type Plugin struct {
	config  config.CustomSessionConfig
	service *services.Service
}

var (
	_ plugins.Plugin                = (*Plugin)(nil)
	_ plugins.EndpointHooksProvider = (*Plugin)(nil)
)

// Option configures the plugin.
type Option func(*Plugin)

// WithMutateListDeviceSessions also maps the multi-session list-device-sessions response.
func WithMutateListDeviceSessions(enable bool) Option {
	return func(p *Plugin) { p.config.ShouldMutateListDeviceSessionsEndpoint = enable }
}

// New creates the plugin with better-auth's customSession(fn) callback.
func New(fn config.Func, opts ...Option) *Plugin {
	p := &Plugin{config: config.CustomSessionConfig{Fn: fn}}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// NewWithConfig creates the plugin from a full configuration.
func NewWithConfig(cfg config.CustomSessionConfig, opts ...Option) *Plugin {
	p := &Plugin{config: cfg}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// ID returns "custom-session".
func (p *Plugin) ID() string { return PluginID }

// Init validates the callback.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	if ictx == nil {
		return errors.New("custom-session: init context is required")
	}
	svc, err := services.New(p.config)
	if err != nil {
		return err
	}
	p.service = svc
	return nil
}

// EndpointHooks returns the after hooks that rewrite the session responses.
func (p *Plugin) EndpointHooks() endpointhooks.Hooks {
	if p.service == nil {
		return endpointhooks.Hooks{}
	}
	return p.service.Hooks()
}

// Migrator returns nil: the plugin has no tables.
func (p *Plugin) Migrator() migration.IMigrator { return nil }

// Services returns nil: the plugin only has hooks.
func (p *Plugin) Services() map[string]any { return nil }

// Routes returns nil: the plugin has no endpoints of its own.
func (p *Plugin) Routes() []plugins.RouteDescriptor { return nil }

// Config returns the configuration.
func (p *Plugin) Config() config.CustomSessionConfig { return p.config }
