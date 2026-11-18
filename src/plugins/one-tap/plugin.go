// Package onetap ports better-auth's one-tap plugin (Google One Tap / Sign in with Google): POST
// /one-tap/callback takes the Google ID token the browser received, verifies it against Google's JWKS and
// signs the user in, links the Google account to an existing user with the same email, or signs a new user
// up, then sets the session cookie and answers {token, user}.
//
// Account linking and token storage follow the social plugin's options when it is passed with
// WithSocialPlugin (which also provides the Google client ID). Accounts are stored with providerId
// "google", so a user signing in with One Tap and with the social plugin's Google provider is one account.
package onetap

import (
	"errors"
	"net/http"

	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	humaonetap "github.com/better-go-auth/goauth/src/plugins/one-tap/adapters/huma"
	"github.com/better-go-auth/goauth/src/plugins/one-tap/config"
	"github.com/better-go-auth/goauth/src/plugins/one-tap/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

// PluginID is better-auth's plugin id.
const PluginID = "one-tap"

// Plugin implements plugins.Plugin for better-auth's one-tap plugin.
type Plugin struct {
	config  config.OneTapConfig
	social  services.SocialSource
	service *services.Service
}

var _ plugins.Plugin = (*Plugin)(nil)

// Option configures the plugin.
type Option func(*Plugin)

// WithClientID sets the Google client ID ID tokens must be issued for.
func WithClientID(id string) Option { return func(p *Plugin) { p.config.ClientID = id } }

// WithDisableSignup refuses to create users for unknown Google accounts.
func WithDisableSignup(disable bool) Option {
	return func(p *Plugin) { p.config.DisableSignup = disable }
}

// WithJWKSURL overrides Google's JWKS URL (tests use a fake key set).
func WithJWKSURL(u string) Option { return func(p *Plugin) { p.config.JWKSURL = u } }

// WithHTTPClient sets the client used to fetch the JWKS.
func WithHTTPClient(c *http.Client) Option { return func(p *Plugin) { p.config.HTTPClient = c } }

// WithSocialPlugin uses the social plugin's account linking / token options and, when ClientID is empty,
// its "google" provider's client ID (pass the *social.Plugin).
func WithSocialPlugin(s services.SocialSource) Option { return func(p *Plugin) { p.social = s } }

// New creates the one-tap plugin.
func New(cfg config.OneTapConfig, opts ...Option) *Plugin {
	p := &Plugin{config: cfg}
	for _, opt := range opts {
		opt(p)
	}
	p.config = p.config.WithDefaults()
	return p
}

// ID returns "one-tap".
func (p *Plugin) ID() string { return PluginID }

// Init builds the service and mounts the endpoint.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	if ictx == nil {
		return errors.New("one-tap: init context is required")
	}
	// Step 1: shared plugin runtime (sessions, cookies, origin check)
	kit, err := pluginkit.New(ictx)
	if err != nil {
		return err
	}
	// Step 2: the service on top of the social plugin's OAuth machinery
	svc, err := services.New(kit, p.config, p.social)
	if err != nil {
		return err
	}
	p.service = svc
	// Step 3: mount POST /one-tap/callback
	humaonetap.RegisterRoutes(ictx.Api, kit, humaonetap.NewHandler(svc))
	return nil
}

// Migrator returns nil: one-tap uses the core user, account and session tables.
func (p *Plugin) Migrator() migration.IMigrator { return nil }

// Services exposes the plugin service.
func (p *Plugin) Services() map[string]any { return map[string]any{"oneTap": p.service} }

// Routes returns nil: the route is mounted on Huma in Init.
func (p *Plugin) Routes() []plugins.RouteDescriptor { return nil }

// Service returns the plugin service (nil before Init).
func (p *Plugin) Service() *services.Service { return p.service }

// Config returns the effective configuration.
func (p *Plugin) Config() config.OneTapConfig { return p.config }
