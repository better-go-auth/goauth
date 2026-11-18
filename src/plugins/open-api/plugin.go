// Package openapi ports better-auth's open-api plugin: GET /open-api/generate-schema returns the OpenAPI
// 3.1 document of the auth routes in better-auth's shape, and GET /reference (configurable) serves the
// Scalar API reference page for it.
//
// The document is derived from the OpenAPI document Huma generates for every goauth route (see the
// services package for the exact rules) and is built on every request, so it always lists the routes of
// every installed plugin, whatever the plugin order.
package openapi

import (
	"errors"
	"strings"

	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	humaopenapi "github.com/better-go-auth/goauth/src/plugins/open-api/adapters/huma"
	"github.com/better-go-auth/goauth/src/plugins/open-api/config"
	"github.com/better-go-auth/goauth/src/plugins/open-api/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/schema"
)

// PluginID is better-auth's plugin id.
const PluginID = "open-api"

// Plugin implements plugins.Plugin for better-auth's open-api plugin.
type Plugin struct {
	config  config.OpenAPIConfig
	service *services.Service
}

var _ plugins.Plugin = (*Plugin)(nil)

// Option configures the plugin.
type Option func(*Plugin)

// WithPath sets the reference page path relative to BasePath (default "/reference").
func WithPath(path string) Option { return func(p *Plugin) { p.config.Path = path } }

// WithDisableDefaultReference turns the reference page off (404).
func WithDisableDefaultReference(disable bool) Option {
	return func(p *Plugin) { p.config.DisableDefaultReference = disable }
}

// WithTheme sets the Scalar theme (default "default").
func WithTheme(theme string) Option { return func(p *Plugin) { p.config.Theme = theme } }

// WithNonce adds a nonce attribute to the page's scripts.
func WithNonce(nonce string) Option { return func(p *Plugin) { p.config.Nonce = nonce } }

// WithSchemaPlugins adds the schemas of plugins implementing plugins.SchemaProvider to
// components.schemas (better-auth includes every installed plugin's schema).
func WithSchemaPlugins(ps ...plugins.Plugin) Option {
	return func(p *Plugin) {
		for _, pl := range ps {
			if sp, ok := pl.(plugins.SchemaProvider); ok && pl != nil {
				p.config.Schemas = append(p.config.Schemas, schema.Plugin{ID: pl.ID(), Schema: sp.Schema()})
			}
		}
	}
}

// New creates the open-api plugin.
func New(cfg config.OpenAPIConfig, opts ...Option) *Plugin {
	p := &Plugin{config: cfg}
	for _, opt := range opts {
		opt(p)
	}
	p.config = p.config.WithDefaults()
	if !strings.HasPrefix(p.config.Path, "/") {
		p.config.Path = "/" + p.config.Path
	}
	return p
}

// ID returns "open-api".
func (p *Plugin) ID() string { return PluginID }

// Init builds the service and mounts the endpoints.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	if ictx == nil {
		return errors.New("open-api: init context is required")
	}
	// Step 1: shared plugin runtime (base path, disabled routes, origin check)
	kit, err := pluginkit.New(ictx)
	if err != nil {
		return err
	}
	// Step 2: the generator reads the Huma document of the same API at request time
	p.service = services.New(ictx.Api, ictx.Config, p.config, kit.BasePath, kit.BaseURL())
	// Step 3: mount the routes
	humaopenapi.RegisterRoutes(ictx.Api, kit, humaopenapi.NewHandler(p.service))
	return nil
}

// Migrator returns nil: the plugin has no tables.
func (p *Plugin) Migrator() migration.IMigrator { return nil }

// Services exposes the plugin service.
func (p *Plugin) Services() map[string]any { return map[string]any{"openAPI": p.service} }

// Routes returns nil: the routes are mounted on Huma in Init.
func (p *Plugin) Routes() []plugins.RouteDescriptor { return nil }

// Service returns the plugin service (nil before Init).
func (p *Plugin) Service() *services.Service { return p.service }

// Config returns the effective configuration.
func (p *Plugin) Config() config.OpenAPIConfig { return p.config }
