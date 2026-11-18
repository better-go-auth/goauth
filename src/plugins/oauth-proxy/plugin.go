// Package oauthproxy ports better-auth's oauth-proxy plugin: OAuth sign-in on preview deployments whose URL
// is not registered at the providers. The provider's callback goes to the production deployment, which
// finishes the code exchange and hands the user's profile, encrypted, to the preview's
// GET /oauth-proxy-callback.
//
// Install it with the same secret on production and every preview deployment, next to the social plugin:
//
//	socialPlugin := social.New(socialconfig.SocialConfig{Providers: ...})
//	proxy := oauthproxy.New(config.OAuthProxyConfig{ProductionURL: "https://my-app.com"},
//		oauthproxy.WithSocial(socialPlugin))
//	goauth.GoAuthOptions{Plugins: []plugins.Plugin{socialPlugin, proxy}, ...}
//
// The plugin has no table: it reuses the social plugin's OAuth state and account linking.
package oauthproxy

import (
	"errors"
	"time"

	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	humaproxy "github.com/better-go-auth/goauth/src/plugins/oauth-proxy/adapters/huma"
	"github.com/better-go-auth/goauth/src/plugins/oauth-proxy/config"
	"github.com/better-go-auth/goauth/src/plugins/oauth-proxy/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/plugins/social"
	socialservices "github.com/better-go-auth/goauth/src/plugins/social/services"
)

// PluginID is better-auth's plugin id.
const PluginID = "oauth-proxy"

// Plugin implements plugins.Plugin for better-auth's oauth-proxy plugin.
type Plugin struct {
	config  config.OAuthProxyConfig
	social  services.SocialService
	service *services.Service
}

var (
	_ plugins.Plugin                = (*Plugin)(nil)
	_ plugins.EndpointHooksProvider = (*Plugin)(nil)
	_ plugins.DependencyProvider    = (*Plugin)(nil)
)

// Option configures the plugin.
type Option func(*Plugin)

// WithSocial connects the social plugin whose providers, OAuth state and account linking the proxy uses
// (better-auth's ctx.context.socialProviders). Generic OAuth providers passed to social.WithProviders are
// reachable too. The plugin's service is looked up at request time, so the plugin order does not matter.
func WithSocial(p *social.Plugin) Option {
	return func(pl *Plugin) {
		if p != nil {
			pl.social = p.Service
		}
	}
}

// WithSocialService sets the function returning the social service (WithSocial does this for you).
func WithSocialService(fn func() *socialservices.Service) Option {
	return func(pl *Plugin) { pl.social = fn }
}

// WithProductionURL sets the production deployment URL.
func WithProductionURL(u string) Option { return func(p *Plugin) { p.config.ProductionURL = u } }

// WithCurrentURL sets the current deployment URL (default: the request URL).
func WithCurrentURL(u string) Option { return func(p *Plugin) { p.config.CurrentURL = u } }

// WithMaxAge sets how long the encrypted profile is accepted (default 60 seconds).
func WithMaxAge(d time.Duration) Option { return func(p *Plugin) { p.config.MaxAge = d } }

// WithSecret sets the encryption secret (default: the auth secret).
func WithSecret(secret string) Option { return func(p *Plugin) { p.config.Secret = secret } }

// New creates the oauth-proxy plugin.
func New(cfg config.OAuthProxyConfig, opts ...Option) *Plugin {
	p := &Plugin{config: cfg}
	for _, opt := range opts {
		opt(p)
	}
	p.config = p.config.WithDefaults()
	return p
}

// ID returns "oauth-proxy".
func (p *Plugin) ID() string { return PluginID }

// Dependencies returns the social plugin: the proxy finishes social OAuth flows.
func (p *Plugin) Dependencies() []string { return []string{social.PluginID} }

// Init builds the service and mounts GET /oauth-proxy-callback.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	if ictx == nil {
		return errors.New("oauth-proxy: init context is required")
	}
	// Step 1: the social plugin is required (WithSocial)
	if p.social == nil {
		return errors.New("oauth-proxy: the social plugin is required (oauthproxy.WithSocial)")
	}
	// Step 2: shared plugin runtime (sessions, cookies, origin checks)
	kit, err := pluginkit.New(ictx)
	if err != nil {
		return err
	}
	// Step 3: service and routes
	p.service = services.New(kit, p.config, p.social)
	humaproxy.RegisterRoutes(ictx.Api, kit, humaproxy.NewHandler(p.service))
	return nil
}

// EndpointHooks returns the sign-in and callback hooks (nil hooks before Init).
func (p *Plugin) EndpointHooks() endpointhooks.Hooks {
	if p.service == nil {
		return endpointhooks.Hooks{}
	}
	return p.service.Hooks()
}

// Migrator returns nil: the plugin has no table.
func (p *Plugin) Migrator() migration.IMigrator { return nil }

// Services exposes the plugin service.
func (p *Plugin) Services() map[string]any { return map[string]any{"oauthProxy": p.service} }

// Routes returns nil: the endpoint is mounted on Huma in Init.
func (p *Plugin) Routes() []plugins.RouteDescriptor { return nil }

// Service returns the plugin service (nil before Init).
func (p *Plugin) Service() *services.Service { return p.service }

// Config returns the effective configuration.
func (p *Plugin) Config() config.OAuthProxyConfig { return p.config }
