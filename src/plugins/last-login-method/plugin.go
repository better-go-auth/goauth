// Package lastloginmethod ports better-auth's last-login-method plugin: after every successful sign-in it
// sets the `better-auth.last_used_login_method` cookie (readable by JavaScript, the session cookie's other
// attributes) to the method used: "email", the OAuth provider id, "magic-link", "passkey", "siwe" or what
// CustomResolveMethod returns. With StoreInDatabase the method is also stored in the user's lastLoginMethod
// field, which the plugin declares through plugins.SchemaProvider.
//
// The cookie is set by an after hook on every endpoint (plugins.EndpointHooksProvider) when the response sets
// the session cookie; the database writes run as better-auth's user.create.before hook and, for the session
// a request created, its session.create.after hook.
package lastloginmethod

import (
	"errors"

	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	llmconfig "github.com/better-go-auth/goauth/src/plugins/last-login-method/config"
	"github.com/better-go-auth/goauth/src/plugins/last-login-method/services"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	"github.com/better-go-auth/goauth/src/schema"
)

// PluginID is better-auth's plugin id.
const PluginID = "last-login-method"

// Plugin implements plugins.Plugin, plugins.EndpointHooksProvider and plugins.SchemaProvider for
// better-auth's last-login-method plugin.
type Plugin struct {
	config  llmconfig.LastLoginMethodConfig
	service *services.Service
}

var (
	_ plugins.Plugin                = (*Plugin)(nil)
	_ plugins.EndpointHooksProvider = (*Plugin)(nil)
	_ plugins.SchemaProvider        = (*Plugin)(nil)
)

// Option configures the plugin.
type Option func(*Plugin)

// WithCookieName sets the cookie name.
func WithCookieName(name string) Option {
	return func(p *Plugin) { p.config.CookieName = name }
}

// WithCustomResolveMethod sets the resolver run before the default rules.
func WithCustomResolveMethod(fn llmconfig.ResolveFunc) Option {
	return func(p *Plugin) { p.config.CustomResolveMethod = fn }
}

// WithStoreInDatabase stores the method in the user's lastLoginMethod field.
func WithStoreInDatabase(store bool) Option {
	return func(p *Plugin) { p.config.StoreInDatabase = store }
}

// New creates the plugin.
func New(cfg llmconfig.LastLoginMethodConfig, opts ...Option) *Plugin {
	p := &Plugin{config: cfg}
	for _, opt := range opts {
		opt(p)
	}
	p.config = p.config.WithDefaults()
	return p
}

// ID returns "last-login-method".
func (p *Plugin) ID() string { return PluginID }

// Schema declares the user's lastLoginMethod field when StoreInDatabase is on (better-auth's plugin schema:
// string, input false, not required, fieldName from FieldName).
func (p *Plugin) Schema() schema.PluginSchema {
	if !p.config.StoreInDatabase {
		return nil
	}
	return schema.PluginSchema{schema.ModelUser: schema.Model{Fields: map[string]schema.Field{
		llmconfig.FieldLastLoginMethod: {
			Type:      schema.String,
			Required:  false,
			Input:     schema.Bool(false),
			FieldName: p.config.FieldName,
		},
	}}}
}

// Init wires the cookie manager and, with StoreInDatabase, the user hooks and the field's storage key.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	if ictx == nil {
		return errors.New("last-login-method: init context is required")
	}
	// Step 1: the session cookie's name and attributes
	cm := ictx.CookieManager
	if cm == nil {
		cm = cookies.New(ictx.Config)
	}
	deps := services.Deps{BasePath: ictx.Config.BasePath, Cookies: cm, Repos: ictx.IAuthRepos}
	// Step 2: where lastLoginMethod lives (registry field for adapter repositories, column for GORM)
	if p.config.StoreInDatabase {
		if ictx.IAuthRepos == nil {
			return errors.New("last-login-method: storeInDatabase needs the repositories")
		}
		// SetupGoAuth's registry already holds this plugin's field; outside it, build one
		reg := ictx.Schema
		if reg == nil {
			opts := ictx.Config.SchemaOptions()
			opts.Plugins = append(opts.Plugins, schema.Plugin{ID: PluginID, Schema: p.Schema()})
			built, err := schema.Build(opts)
			if err != nil {
				return err
			}
			reg = built
		}
		deps.UpdateKey = llmconfig.FieldLastLoginMethod
		if ictx.Adapter == nil && ictx.DB != nil {
			deps.UpdateKey = reg.Column(schema.ModelUser, llmconfig.FieldLastLoginMethod)
			deps.DB = ictx.DB
		}
	}
	p.service = services.New(p.config, deps)
	// Step 3: better-auth's user.create.before (plus the GORM write after insert)
	if p.config.StoreInDatabase && ictx.Hooks != nil {
		ictx.Hooks.OnBeforeUserCreate(p.service.BeforeUserCreate)
		ictx.Hooks.OnAfterUserCreate(p.service.AfterUserCreate)
	}
	return nil
}

// EndpointHooks returns the after hook that sets the cookie (and stores the method for new sessions).
func (p *Plugin) EndpointHooks() endpointhooks.Hooks {
	if p.service == nil {
		return endpointhooks.Hooks{}
	}
	return endpointhooks.Hooks{After: []endpointhooks.AfterHook{{Handler: p.service.AfterHook}}}
}

// Migrator returns nil: the lastLoginMethod column comes from the plugin schema (Schema).
func (p *Plugin) Migrator() migration.IMigrator { return nil }

// Services exposes the service.
func (p *Plugin) Services() map[string]any { return map[string]any{"lastLoginMethod": p.service} }

// Routes returns nil: the plugin has no endpoints.
func (p *Plugin) Routes() []plugins.RouteDescriptor { return nil }

// Service returns the service (nil before Init).
func (p *Plugin) Service() *services.Service { return p.service }

// Config returns the effective configuration.
func (p *Plugin) Config() llmconfig.LastLoginMethodConfig { return p.config }
