// Package scim is goauth's port of better-auth's scim plugin (@better-auth/scim 1.6.16): SCIM 2.0 user
// provisioning for identity providers (Okta, Entra ID, ...).
//
//	scim.New(scimconfig.SCIMConfig{ProviderOwnership: true})
//
// A signed-in user generates a SCIM token for a provider (POST /scim/generate-token, optionally scoped to an
// organization they administer); the identity provider then calls /scim/v2/Users (create, list with
// `userName eq` filter, get, PUT, PATCH, DELETE) with `Authorization: Bearer <token>`. The metadata endpoints
// /scim/v2/ServiceProviderConfig, /scim/v2/Schemas and /scim/v2/ResourceTypes are public.
//
// Connections live in the scimProvider table (plugins.SchemaProvider, created by goauth's migrator).
// Organization scoping needs the organization plugin (plugins.OrganizationStoreProvider).
package scim

import (
	"errors"
	"fmt"

	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	humascim "github.com/better-go-auth/goauth/src/plugins/scim/adapters/huma"
	scimconfig "github.com/better-go-auth/goauth/src/plugins/scim/config"
	"github.com/better-go-auth/goauth/src/plugins/scim/services"
	"github.com/better-go-auth/goauth/src/schema"
)

// PluginID is better-auth's plugin id.
const PluginID = "scim"

// Plugin implements plugins.Plugin and plugins.SchemaProvider for better-auth's scim plugin.
type Plugin struct {
	config  scimconfig.SCIMConfig
	service *services.Service
}

var (
	_ plugins.Plugin         = (*Plugin)(nil)
	_ plugins.SchemaProvider = (*Plugin)(nil)
)

// New creates the scim plugin.
func New(cfg scimconfig.SCIMConfig) *Plugin {
	return &Plugin{config: cfg.WithDefaults()}
}

// ID returns "scim".
func (p *Plugin) ID() string { return PluginID }

// Schema declares the scimProvider table (userId only with ProviderOwnership).
func (p *Plugin) Schema() schema.PluginSchema {
	fields := map[string]schema.Field{
		"providerId":     {Type: schema.String, Required: true, Unique: true},
		"scimToken":      {Type: schema.String, Required: true, Unique: true},
		"organizationId": {Type: schema.String, Required: false},
	}
	if p.config.ProviderOwnership {
		fields["userId"] = schema.Field{Type: schema.String, Required: false}
	}
	return schema.PluginSchema{services.Model: {Fields: fields}}
}

// Init builds the service and mounts the endpoints.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	// Step 1: shared plugin runtime
	if ictx == nil {
		return errors.New("scim plugin: init context is required")
	}
	kit, err := pluginkit.New(ictx)
	if err != nil {
		return fmt.Errorf("scim plugin: %w", err)
	}
	// Step 2: the service over the scimProvider table
	svc, err := services.New(kit, p.config, ictx.Adapter, ictx.Plugins)
	if err != nil {
		return fmt.Errorf("scim plugin: %w", err)
	}
	p.service = svc
	// Step 3: routes
	humascim.Register(kit, ictx.Api, humascim.NewHandler(svc))
	return nil
}

// Migrator returns nil: the scimProvider table comes from the plugin schema (Schema).
func (p *Plugin) Migrator() migration.IMigrator { return nil }

// Services exposes the service.
func (p *Plugin) Services() map[string]any { return map[string]any{"scim": p.service} }

// Routes returns nil: the endpoints are mounted on the Huma API in Init.
func (p *Plugin) Routes() []plugins.RouteDescriptor { return nil }

// Service returns the service (nil before Init).
func (p *Plugin) Service() *services.Service { return p.service }

// Config returns the effective configuration.
func (p *Plugin) Config() scimconfig.SCIMConfig { return p.config }
