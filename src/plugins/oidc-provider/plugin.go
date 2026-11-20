// Package oidcprovider ports better-auth's oidc-provider plugin: goauth becomes an OpenID Connect provider
// (authorization server) for other applications.
//
//   - GET  /.well-known/openid-configuration   discovery document (under the auth base path)
//   - GET  /oauth2/authorize                    authorization code flow (PKCE S256/plain, prompt, max_age, nonce)
//   - POST /oauth2/consent                      accept or deny a consent request
//   - POST /oauth2/token                        authorization_code and refresh_token grants
//   - GET  /oauth2/userinfo                     claims of the access token's scopes
//   - POST /oauth2/register                     RFC 7591 dynamic client registration
//   - GET  /oauth2/client/{id}                  public client info (session required)
//   - GET|POST /oauth2/endsession               RP-initiated logout
//
// Clients live in the oauthApplication table (or Config.TrustedClients), tokens in oauthAccessToken and
// consents in oauthConsent; the plugin declares them with plugins.SchemaProvider. id_tokens are signed
// with HS256 and the client secret, or with the jwt plugin's key pair (Config.UseJWTPlugin, JWKS at /jwks).
// An after hook on every endpoint resumes an authorization request once the user signed in on the login
// page (signed oidc_login_prompt cookie).
package oidcprovider

import (
	"errors"
	"net/http"

	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	humaoidc "github.com/better-go-auth/goauth/src/plugins/oidc-provider/adapters/huma"
	oidcconfig "github.com/better-go-auth/goauth/src/plugins/oidc-provider/config"
	"github.com/better-go-auth/goauth/src/plugins/oidc-provider/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/schema"
)

// PluginID is better-auth's plugin id.
const PluginID = "oidc-provider"

// jwtPluginID is the id of the jwt plugin used with UseJWTPlugin.
const jwtPluginID = "jwt"

// Plugin implements plugins.Plugin, plugins.SchemaProvider and plugins.EndpointHooksProvider.
type Plugin struct {
	config  oidcconfig.Config
	service *services.Service
}

var (
	_ plugins.Plugin                = (*Plugin)(nil)
	_ plugins.SchemaProvider        = (*Plugin)(nil)
	_ plugins.EndpointHooksProvider = (*Plugin)(nil)
	_ plugins.DependencyProvider    = (*Plugin)(nil)
)

// New creates the plugin. cfg.LoginPage is required.
func New(cfg oidcconfig.Config) *Plugin {
	return &Plugin{config: cfg.WithDefaults()}
}

// ID returns "oidc-provider".
func (p *Plugin) ID() string { return PluginID }

// Dependencies requires the jwt plugin when id_tokens are signed with it (better-auth fails at the token
// endpoint instead; goauth refuses to start).
func (p *Plugin) Dependencies() []string {
	if p.config.UseJWTPlugin {
		return []string{jwtPluginID}
	}
	return nil
}

// Schema declares oauthApplication, oauthAccessToken and oauthConsent (with Config.Schema renames).
func (p *Plugin) Schema() schema.PluginSchema { return services.Schema(p.config.Schema) }

// Init builds the service and mounts the endpoints.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	// Step 1: dependencies
	if ictx == nil {
		return errors.New("oidc-provider: init context is required")
	}
	if p.config.LoginPage == "" {
		return errors.New("oidc-provider: LoginPage is required")
	}
	if ictx.Adapter == nil {
		return errors.New("oidc-provider: the plugin tables need InitContext.Adapter (a Conn or adapter-based repositories)")
	}
	kit, err := pluginkit.New(ictx)
	if err != nil {
		return err
	}
	// Step 2: the service (the jwt plugin is looked up when used, like better-auth's getPlugin)
	lookup := ictx.Plugin
	p.service = services.New(p.config, services.Deps{
		Kit:   kit,
		Store: ictx.Adapter,
		JWT: func() services.JWTSigner {
			if lookup == nil {
				return nil
			}
			if j, ok := lookup(jwtPluginID).(services.JWTSigner); ok {
				return j
			}
			return nil
		},
	})
	// Step 3: the endpoints
	humaoidc.RegisterRoutes(ictx.Api, kit, &humaoidc.Handler{Service: p.service})
	return nil
}

// EndpointHooks returns the after hook resuming the authorization request after login.
func (p *Plugin) EndpointHooks() endpointhooks.Hooks {
	if p.service == nil {
		return endpointhooks.Hooks{}
	}
	return endpointhooks.Hooks{After: []endpointhooks.AfterHook{{Handler: func(c *endpointhooks.Context) (*endpointhooks.Response, error) {
		return p.service.ResumeAfterLogin(c, p.service.Authorize)
	}}}}
}

// MetadataHandler serves the discovery document as a plain http.Handler, to mount it where OpenID
// Connect clients look for it (<issuer>/.well-known/openid-configuration, outside the auth base path).
func (p *Plugin) MetadataHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.service == nil {
			http.Error(w, "oidc-provider: not initialized", http.StatusServiceUnavailable)
			return
		}
		// the request (and, with a dynamic base URL, its origin) like goauth's own routes see it
		ctx := config.WithHTTPRequest(r.Context(), r)
		if conf := p.service.Kit().Conf; conf.DynamicBaseURL != nil {
			if origin, err := conf.ResolveBaseURL(r); err == nil && origin != "" {
				ctx = config.WithRequestBaseURL(ctx, origin)
			}
		}
		res := services.JSON(http.StatusOK, p.service.Metadata(ctx))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(res.Status)
		_, _ = w.Write(res.Body)
	})
}

// Migrator returns nil: the tables come from the plugin schema.
func (p *Plugin) Migrator() migration.IMigrator { return nil }

// Services exposes the service.
func (p *Plugin) Services() map[string]any { return map[string]any{"oidcProvider": p.service} }

// Routes returns nil: the endpoints are Huma operations.
func (p *Plugin) Routes() []plugins.RouteDescriptor { return nil }

// Service returns the service (nil before Init).
func (p *Plugin) Service() *services.Service { return p.service }

// Config returns the effective configuration.
func (p *Plugin) Config() oidcconfig.Config { return p.config }
