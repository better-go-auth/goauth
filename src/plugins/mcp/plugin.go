// Package mcp ports better-auth's mcp plugin: goauth becomes the OAuth authorization server of MCP (Model
// Context Protocol) servers. MCP clients discover it, register themselves, run the authorization code
// flow with PKCE and call the MCP server with the access token, which the MCP server validates with
// WithMcpAuth / Middleware.
//
//   - GET  /.well-known/oauth-authorization-server   RFC 8414 metadata (under the auth base path)
//   - GET  /.well-known/oauth-protected-resource     RFC 9728 metadata
//   - GET  /mcp/authorize                            authorization code flow (PKCE)
//   - POST /mcp/token                                authorization_code and refresh_token grants
//   - POST /mcp/register                             open dynamic client registration (public clients)
//   - GET  /mcp/get-session                          the access token record of a bearer token
//   - POST /oauth2/consent                           consent (prompt=consent with a consent page)
//
// The tables are the oidc-provider's (oauthApplication, oauthAccessToken, oauthConsent); install either
// the mcp plugin or the oidc-provider, not both (they share /oauth2/consent, as in better-auth).
package mcp

import (
	"errors"

	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	humamcp "github.com/better-go-auth/goauth/src/plugins/mcp/adapters/huma"
	mcpconfig "github.com/better-go-auth/goauth/src/plugins/mcp/config"
	"github.com/better-go-auth/goauth/src/plugins/mcp/services"
	oidc "github.com/better-go-auth/goauth/src/plugins/oidc-provider/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/schema"
)

// PluginID is better-auth's plugin id.
const PluginID = "mcp"

// Plugin implements plugins.Plugin, plugins.SchemaProvider and plugins.EndpointHooksProvider.
type Plugin struct {
	config  mcpconfig.Config
	service *services.Service
}

var (
	_ plugins.Plugin                = (*Plugin)(nil)
	_ plugins.SchemaProvider        = (*Plugin)(nil)
	_ plugins.EndpointHooksProvider = (*Plugin)(nil)
)

// New creates the plugin. cfg.LoginPage is required.
func New(cfg mcpconfig.Config) *Plugin {
	return &Plugin{config: cfg}
}

// ID returns "mcp".
func (p *Plugin) ID() string { return PluginID }

// Schema declares the oidc-provider tables (better-auth's mcp schema is the oidc-provider schema).
func (p *Plugin) Schema() schema.PluginSchema { return oidc.Schema(nil) }

// Init builds the service and mounts the endpoints.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	// Step 1: dependencies
	if ictx == nil {
		return errors.New("mcp: init context is required")
	}
	if p.config.LoginPage == "" {
		return errors.New("mcp: LoginPage is required")
	}
	if ictx.Adapter == nil {
		return errors.New("mcp: the plugin tables need InitContext.Adapter (a Conn or adapter-based repositories)")
	}
	kit, err := pluginkit.New(ictx)
	if err != nil {
		return err
	}
	// Step 2: the oidc-provider underneath (better-auth's oidcProvider({...opts}))
	provider := oidc.New(p.config.ProviderConfig(), oidc.Deps{Kit: kit, Store: ictx.Adapter})
	p.service = services.New(p.config, provider)
	// Step 3: the endpoints
	humamcp.RegisterRoutes(ictx.Api, kit, &humamcp.Handler{Service: p.service})
	return nil
}

// EndpointHooks returns the after hook resuming /mcp/authorize after login.
func (p *Plugin) EndpointHooks() endpointhooks.Hooks {
	if p.service == nil {
		return endpointhooks.Hooks{}
	}
	return endpointhooks.Hooks{After: []endpointhooks.AfterHook{{Handler: func(c *endpointhooks.Context) (*endpointhooks.Response, error) {
		return p.service.Provider.ResumeAfterLogin(c, p.service.Authorize)
	}}}}
}

// Migrator returns nil: the tables come from the plugin schema.
func (p *Plugin) Migrator() migration.IMigrator { return nil }

// Services exposes the service.
func (p *Plugin) Services() map[string]any { return map[string]any{"mcp": p.service} }

// Routes returns nil: the endpoints are Huma operations.
func (p *Plugin) Routes() []plugins.RouteDescriptor { return nil }

// Service returns the service (nil before Init).
func (p *Plugin) Service() *services.Service { return p.service }

// Config returns the configuration.
func (p *Plugin) Config() mcpconfig.Config { return p.config }
