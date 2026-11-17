// Package genericoauth is goauth's port of better-auth's generic-oauth plugin: sign-in with any OAuth 2.0 /
// OpenID Connect provider (POST /sign-in/oauth2, GET /oauth2/callback/{providerId}, POST /oauth2/link).
//
//	genericoauth.New(genericoauthconfig.Config{
//		Providers: []genericoauthconfig.ProviderConfig{
//			{ProviderID: "acme", DiscoveryURL: "https://idp.acme.com/.well-known/openid-configuration",
//				ClientID: id, ClientSecret: secret, Scopes: []string{"openid", "email", "profile"}, PKCE: true},
//			gproviders.Keycloak(gproviders.IssuerOptions{Issuer: issuer, PresetOptions: gproviders.PresetOptions{ClientID: id, ClientSecret: secret}}),
//		},
//	})
//
// The OAuth machinery (state + PKCE, account linking, token storage) is the social plugin's. better-auth also
// registers generic providers as social providers; in goauth pass Plugin.SocialProviders() to the social
// plugin (social.WithProviders(...)) to get /sign-in/social, /get-access-token, /refresh-token and
// /account-info for them.
package genericoauth

import (
	"fmt"

	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	humagenericoauth "github.com/better-go-auth/goauth/src/plugins/generic-oauth/adapters/huma"
	"github.com/better-go-auth/goauth/src/plugins/generic-oauth/config"
	gproviders "github.com/better-go-auth/goauth/src/plugins/generic-oauth/providers"
	"github.com/better-go-auth/goauth/src/plugins/generic-oauth/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	socialconfig "github.com/better-go-auth/goauth/src/plugins/social/config"
	socialproviders "github.com/better-go-auth/goauth/src/plugins/social/providers"
)

// PluginID is better-auth's plugin id.
const PluginID = "generic-oauth"

// ErrorCodes are better-auth's GENERIC_OAUTH_ERROR_CODES.
var ErrorCodes = services.ErrorCodes

// Plugin implements plugins.Plugin for better-auth's generic-oauth plugin.
type Plugin struct {
	config    config.Config
	providers []*gproviders.Provider
	service   *services.Service
	handler   *humagenericoauth.Handler
}

var _ plugins.Plugin = (*Plugin)(nil)

// Option configures the plugin on top of the config struct.
type Option func(*Plugin)

// WithProviders appends provider configs.
func WithProviders(ps ...config.ProviderConfig) Option {
	return func(p *Plugin) { p.config.Providers = append(p.config.Providers, ps...) }
}

// WithAccountLinking replaces the account linking policy.
func WithAccountLinking(l socialconfig.AccountLinking) Option {
	return func(p *Plugin) { p.config.AccountLinking = l }
}

// WithStateStrategy selects the OAuth state storage ("database" or "cookie").
func WithStateStrategy(s socialconfig.StateStrategy) Option {
	return func(p *Plugin) { p.config.StoreStateStrategy = s }
}

// New creates the generic-oauth plugin.
func New(cfg config.Config, opts ...Option) *Plugin {
	// Step 1: the config, then the functional overrides
	p := &Plugin{config: cfg}
	for _, opt := range opts {
		opt(p)
	}
	// Step 2: defaults
	if p.config.StoreStateStrategy == "" {
		p.config.StoreStateStrategy = socialconfig.StateDatabase
	}
	// Step 3: one adapter per provider (they share the discovery cache across endpoints)
	for _, pc := range p.config.Providers {
		p.providers = append(p.providers, gproviders.New(pc, p.config.CacheTTL()))
	}
	return p
}

// ID returns the plugin identifier.
func (p *Plugin) ID() string { return PluginID }

// Init builds the service and mounts the endpoints.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	// Step 1: shared plugin runtime (cookies, sessions, origin checks, repositories)
	kit, err := pluginkit.New(ictx)
	if err != nil {
		return fmt.Errorf("generic-oauth plugin: %w", err)
	}
	// Step 2: validate the strategy and build the service
	switch p.config.StoreStateStrategy {
	case socialconfig.StateDatabase, socialconfig.StateCookie:
	default:
		return fmt.Errorf("generic-oauth plugin: unknown state strategy %q", p.config.StoreStateStrategy)
	}
	svc, err := services.New(kit, p.config, p.providers)
	if err != nil {
		return fmt.Errorf("generic-oauth plugin: %w", err)
	}
	p.service = svc
	p.handler = humagenericoauth.NewHandler(svc)
	// Step 3: routes
	humagenericoauth.Register(kit, ictx.Api, p.handler)
	return nil
}

// Migrator returns nil: the plugin uses the core user, account and verification tables.
func (p *Plugin) Migrator() migration.IMigrator { return nil }

// Services exposes the generic-oauth service.
func (p *Plugin) Services() map[string]any { return map[string]any{"generic-oauth": p.service} }

// Routes returns nil: the endpoints are mounted on the Huma API in Init.
func (p *Plugin) Routes() []plugins.RouteDescriptor { return nil }

// Service returns the initialized service.
func (p *Plugin) Service() *services.Service { return p.service }

// Config returns the effective configuration.
func (p *Plugin) Config() config.Config { return p.config }

// SocialProviders returns the configured providers adapted to the social plugin's provider interface
// (better-auth concatenates them into ctx.socialProviders). Pass them to social.WithProviders to use them with
// /sign-in/social and the account token endpoints; that flow then uses the social /callback/{id} route.
func (p *Plugin) SocialProviders() []socialproviders.Provider {
	out := make([]socialproviders.Provider, 0, len(p.providers))
	seen := map[string]bool{}
	for _, gp := range p.providers {
		if seen[gp.ID()] {
			continue
		}
		seen[gp.ID()] = true
		out = append(out, gp)
	}
	return out
}
