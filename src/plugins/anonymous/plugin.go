// Package anonymous ports better-auth's anonymous plugin: anonymous sign-in, deleting anonymous users, and
// linking an anonymous user to the account it later signs in to or signs up for (OnLinkAccount, then the
// anonymous user is deleted).
//
// The isAnonymous column lives on the core user table, so the plugin has no migrator. Linking uses the core
// OnNewSession hook (plugins.NewSessionEvent), which fires for every core and plugin endpoint.
package anonymous

import (
	"errors"

	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	humaanonymous "github.com/better-go-auth/goauth/src/plugins/anonymous/adapters/huma"
	"github.com/better-go-auth/goauth/src/plugins/anonymous/config"
	"github.com/better-go-auth/goauth/src/plugins/anonymous/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

// PluginID is better-auth's plugin id.
const PluginID = "anonymous"

// ErrorCodes are better-auth's ANONYMOUS_ERROR_CODES.
var ErrorCodes = services.ErrorCodes

// Plugin implements plugins.Plugin for better-auth's anonymous plugin.
type Plugin struct {
	config  config.AnonymousConfig
	kit     *pluginkit.Kit
	service *services.Service
	handler *humaanonymous.Handler
}

var _ plugins.Plugin = (*Plugin)(nil)

// Option configures the plugin.
type Option func(*Plugin)

// WithEmailDomainName builds anonymous emails as "temp-<id>@<domain>".
func WithEmailDomainName(domain string) Option {
	return func(p *Plugin) { p.config.EmailDomainName = domain }
}

// WithGenerateName names new anonymous users.
func WithGenerateName(fn config.GenerateNameFunc) Option {
	return func(p *Plugin) { p.config.GenerateName = fn }
}

// WithGenerateRandomEmail replaces the generated anonymous email.
func WithGenerateRandomEmail(fn config.GenerateRandomEmailFunc) Option {
	return func(p *Plugin) { p.config.GenerateRandomEmail = fn }
}

// WithOnLinkAccount runs fn when an anonymous user signs in to an account.
func WithOnLinkAccount(fn config.OnLinkAccountFunc) Option {
	return func(p *Plugin) { p.config.OnLinkAccount = fn }
}

// WithDisableDeleteAnonymousUser keeps anonymous users after linking and disables /delete-anonymous-user.
func WithDisableDeleteAnonymousUser(disable bool) Option {
	return func(p *Plugin) { p.config.DisableDeleteAnonymousUser = disable }
}

// New creates the anonymous plugin.
func New(cfg config.AnonymousConfig, opts ...Option) *Plugin {
	p := &Plugin{config: cfg}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// ID returns "anonymous".
func (p *Plugin) ID() string { return PluginID }

// Init builds the service, registers the linking hook and mounts the endpoints.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	if ictx == nil {
		return errors.New("anonymous: init context is required")
	}
	// Step 1: shared plugin runtime (sessions, cookies, origin check, rate limiter)
	kit, err := pluginkit.New(ictx)
	if err != nil {
		return err
	}
	p.kit = kit
	// Step 2: service
	p.service = services.NewService(p.config, kit)
	// Step 3: account linking runs whenever a response hands out a new session
	if ictx.Hooks != nil {
		ictx.Hooks.OnNewSession(p.service.OnNewSession)
	}
	// Step 4: mount the routes
	p.handler = humaanonymous.NewHandler(p.service)
	humaanonymous.RegisterRoutes(ictx.Api, kit, p.handler)
	return nil
}

// Migrator returns nil: the plugin's column is part of the core user table.
func (p *Plugin) Migrator() migration.IMigrator { return nil }

// Services exposes the plugin service.
func (p *Plugin) Services() map[string]any { return map[string]any{"anonymous": p.service} }

// Routes returns nil: routes are mounted on Huma in Init.
func (p *Plugin) Routes() []plugins.RouteDescriptor { return nil }

// Service returns the plugin service (nil before Init).
func (p *Plugin) Service() *services.Service { return p.service }

// Config returns the configuration.
func (p *Plugin) Config() config.AnonymousConfig { return p.config }
