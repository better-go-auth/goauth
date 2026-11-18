// Package social is goauth's port of better-auth's social sign-in (OAuth 2.0 / OpenID Connect):
// POST /sign-in/social, GET|POST /callback/{id}, POST /link-social, POST /get-access-token,
// POST /refresh-token and GET /account-info.
//
//	social.New(socialconfig.SocialConfig{
//		Providers: []providers.Provider{
//			providers.Google(providers.GoogleOptions{ProviderOptions: providers.ProviderOptions{ClientID: id, ClientSecret: secret}}),
//		},
//	})
package social

import (
	"fmt"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	humasocial "github.com/better-go-auth/goauth/src/plugins/social/adapters/huma"
	socialconfig "github.com/better-go-auth/goauth/src/plugins/social/config"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
	"github.com/better-go-auth/goauth/src/plugins/social/services"
)

// PluginID is the plugin identifier.
const PluginID = "social"

// Plugin implements plugins.Plugin for social sign-in.
type Plugin struct {
	config  socialconfig.SocialConfig
	service *services.Service
	handler *humasocial.Handler
}

var _ plugins.Plugin = (*Plugin)(nil)

// Option configures the plugin on top of the config struct.
type Option func(*Plugin)

// WithProviders appends providers.
func WithProviders(ps ...providers.Provider) Option {
	return func(p *Plugin) { p.config.Providers = append(p.config.Providers, ps...) }
}

// WithAccountLinking replaces the account linking policy.
func WithAccountLinking(l socialconfig.AccountLinking) Option {
	return func(p *Plugin) { p.config.AccountLinking = l }
}

// WithEncryptOAuthTokens stores provider tokens encrypted.
func WithEncryptOAuthTokens(on bool) Option {
	return func(p *Plugin) { p.config.EncryptOAuthTokens = on }
}

// WithStateStrategy selects the OAuth state storage ("database" or "cookie").
func WithStateStrategy(s socialconfig.StateStrategy) Option {
	return func(p *Plugin) { p.config.StoreStateStrategy = s }
}

// New creates the social sign-in plugin.
func New(cfg socialconfig.SocialConfig, opts ...Option) *Plugin {
	// Step 1: the config, then the functional overrides
	p := &Plugin{config: cfg}
	for _, opt := range opts {
		opt(p)
	}
	// Step 2: defaults
	if p.config.StoreStateStrategy == "" {
		p.config.StoreStateStrategy = socialconfig.StateDatabase
	}
	return p
}

// FromAuthConfig builds the plugin for better-auth's core options: AuthConfig.SocialProviders plus the OAuth
// fields of AuthConfig.Account (account linking, token encryption, state strategy). goauth.SetupGoAuth installs
// it automatically when SocialProviders is set, so `betterAuth({ socialProviders, account })` ports 1:1.
func FromAuthConfig(conf config.AuthConfig) *Plugin {
	acc := conf.Account
	return New(socialconfig.SocialConfig{
		Providers: append([]providers.Provider(nil), conf.SocialProviders...),
		AccountLinking: socialconfig.AccountLinking{
			Enabled:                   acc.AccountLinking.Enabled,
			TrustedProviders:          acc.AccountLinking.TrustedProviders,
			AllowDifferentEmails:      acc.AccountLinking.AllowDifferentEmails,
			DisableImplicitLinking:    acc.AccountLinking.DisableImplicitLinking,
			UpdateUserInfoOnLink:      acc.AccountLinking.UpdateUserInfoOnLink,
			RequireLocalEmailVerified: acc.AccountLinking.RequireLocalEmailVerified,
		},
		EncryptOAuthTokens:    acc.EncryptOAuthTokens,
		UpdateAccountOnSignIn: acc.UpdateAccountOnSignIn,
		StoreStateStrategy:    socialconfig.StateStrategy(acc.StoreStateStrategy),
		SkipStateCookieCheck:  acc.SkipStateCookieCheck,
	})
}

// AddProviders appends providers before Init (used for AuthConfig.SocialProviders and generic-oauth providers).
// A provider whose id is already configured is an error.
func (p *Plugin) AddProviders(ps ...providers.Provider) error {
	for _, np := range ps {
		if np == nil {
			continue
		}
		if p.HasProvider(np.ID()) {
			return fmt.Errorf("social plugin: provider %q is configured twice", np.ID())
		}
		p.config.Providers = append(p.config.Providers, np)
	}
	return nil
}

// HasProvider reports whether a provider with id is configured.
func (p *Plugin) HasProvider(id string) bool {
	for _, existing := range p.config.Providers {
		if existing != nil && existing.ID() == id {
			return true
		}
	}
	return false
}

// ID returns the plugin identifier.
func (p *Plugin) ID() string { return PluginID }

// Init builds the service and mounts the endpoints.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	// Step 1: shared plugin runtime (cookies, sessions, origin checks, repositories)
	kit, err := pluginkit.New(ictx)
	if err != nil {
		return fmt.Errorf("social plugin: %w", err)
	}
	// Step 2: validate the strategy and build the service
	switch p.config.StoreStateStrategy {
	case socialconfig.StateDatabase, socialconfig.StateCookie:
	default:
		return fmt.Errorf("social plugin: unknown state strategy %q", p.config.StoreStateStrategy)
	}
	svc, err := services.New(kit, p.config)
	if err != nil {
		return fmt.Errorf("social plugin: %w", err)
	}
	p.service = svc
	p.handler = humasocial.NewHandler(svc)
	// Step 3: routes
	humasocial.Register(kit, ictx.Api, p.handler)
	return nil
}

// Migrator returns nil: social sign-in uses the core user, account and verification tables.
func (p *Plugin) Migrator() migration.IMigrator { return nil }

// Services exposes the social service.
func (p *Plugin) Services() map[string]any { return map[string]any{"social": p.service} }

// Routes returns nil: the endpoints are mounted on the Huma API in Init.
func (p *Plugin) Routes() []plugins.RouteDescriptor { return nil }

// Service returns the initialized service.
func (p *Plugin) Service() *services.Service { return p.service }

// Config returns the effective configuration.
func (p *Plugin) Config() socialconfig.SocialConfig { return p.config }
