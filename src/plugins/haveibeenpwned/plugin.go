// Package haveibeenpwned ports better-auth's have-i-been-pwned plugin: before a configured endpoint
// (default /sign-up/email, /change-password, /reset-password) hashes a new password, the password is looked
// up in the Pwned Passwords range API with k-anonymity (only the first five characters of its SHA-1 hash
// leave the server). A compromised password fails the request with 400 PASSWORD_COMPROMISED.
//
// better-auth wraps ctx.password.hash; goauth runs the check as a password-hash hook
// (plugins.HookRegistry.OnPasswordHash), which every endpoint hashing a new password goes through
// (authcrypto.Passwords.HashContext). The plugin has no routes and no tables.
package haveibeenpwned

import (
	"errors"
	"net/http"

	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	hibpconfig "github.com/better-go-auth/goauth/src/plugins/haveibeenpwned/config"
	"github.com/better-go-auth/goauth/src/plugins/haveibeenpwned/services"
)

// PluginID is better-auth's plugin id.
const PluginID = "have-i-been-pwned"

// Plugin implements plugins.Plugin for better-auth's have-i-been-pwned plugin.
type Plugin struct {
	config  hibpconfig.HaveIBeenPwnedConfig
	service *services.Service
}

var _ plugins.Plugin = (*Plugin)(nil)

// Option configures the plugin.
type Option func(*Plugin)

// WithPaths replaces the checked endpoint paths.
func WithPaths(paths ...string) Option {
	return func(p *Plugin) { p.config.Paths = paths }
}

// WithCustomMessage replaces the PASSWORD_COMPROMISED message.
func WithCustomMessage(msg string) Option {
	return func(p *Plugin) { p.config.CustomPasswordCompromisedMessage = msg }
}

// WithEnabled turns the check on or off.
func WithEnabled(enabled bool) Option {
	return func(p *Plugin) { p.config.Enabled = &enabled }
}

// WithAPIURL replaces the range API base URL (the SHA-1 prefix is appended).
func WithAPIURL(u string) Option {
	return func(p *Plugin) { p.config.APIURL = u }
}

// WithHTTPClient sets the client used for the range API.
func WithHTTPClient(c *http.Client) Option {
	return func(p *Plugin) { p.config.HTTPClient = c }
}

// New creates the plugin.
func New(cfg hibpconfig.HaveIBeenPwnedConfig, opts ...Option) *Plugin {
	p := &Plugin{config: cfg}
	for _, opt := range opts {
		opt(p)
	}
	p.config = p.config.WithDefaults()
	return p
}

// ID returns "have-i-been-pwned".
func (p *Plugin) ID() string { return PluginID }

// Init registers the password-hash hook.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	if ictx == nil {
		return errors.New("have-i-been-pwned: init context is required")
	}
	if ictx.Hooks == nil {
		return errors.New("have-i-been-pwned: a hook registry is required")
	}
	// Step 1: the checker knows the base path to resolve endpoint paths
	p.service = services.New(p.config, ictx.Config.BasePath)
	// Step 2: run it before every new password is hashed
	ictx.Hooks.OnPasswordHash(p.service.BeforeHash)
	return nil
}

// Migrator returns nil: the plugin has no tables.
func (p *Plugin) Migrator() migration.IMigrator { return nil }

// Services exposes the checker.
func (p *Plugin) Services() map[string]any { return map[string]any{"haveIBeenPwned": p.service} }

// Routes returns nil: the plugin has no endpoints.
func (p *Plugin) Routes() []plugins.RouteDescriptor { return nil }

// Service returns the checker (nil before Init).
func (p *Plugin) Service() *services.Service { return p.service }

// Config returns the effective configuration.
func (p *Plugin) Config() hibpconfig.HaveIBeenPwnedConfig { return p.config }
