// Package captcha ports better-auth's captcha plugin: requests to the protected endpoints (default
// /sign-up/email, /sign-in/email, /request-password-reset) must carry the token of a captcha widget in the
// `x-captcha-response` header, which is verified with Cloudflare Turnstile, Google reCAPTCHA (v2 / v3 with
// a minimum score), hCaptcha or CaptchaFox before goauth handles the request.
//
// Like better-auth's `onRequest`, the check runs before everything else (rate limiter, origin check, body
// validation) through plugins.RequestHooksProvider. The plugin has no routes and no tables.
package captcha

import (
	"errors"
	"net/http"

	humaadapter "github.com/better-go-auth/goauth/src/app/adapters/huma"
	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/captcha/config"
	"github.com/better-go-auth/goauth/src/plugins/captcha/services"
	"github.com/better-go-auth/goauth/src/providers/ratelimit"
)

// PluginID is better-auth's plugin id.
const PluginID = "captcha"

// Plugin implements plugins.Plugin and plugins.RequestHooksProvider for better-auth's captcha plugin.
type Plugin struct {
	config  config.CaptchaConfig
	service *services.Service
}

var (
	_ plugins.Plugin               = (*Plugin)(nil)
	_ plugins.RequestHooksProvider = (*Plugin)(nil)
)

// Option configures the plugin.
type Option func(*Plugin)

// WithEndpoints replaces the protected endpoints (default config.DefaultEndpoints).
func WithEndpoints(endpoints ...string) Option {
	return func(p *Plugin) { p.config.Endpoints = endpoints }
}

// WithSiteVerifyURL overrides the provider's verification URL.
func WithSiteVerifyURL(u string) Option {
	return func(p *Plugin) { p.config.SiteVerifyURLOverride = u }
}

// WithMinScore sets the reCAPTCHA v3 minimum score (default 0.5).
func WithMinScore(score float64) Option {
	return func(p *Plugin) { p.config.MinScore = &score }
}

// WithSiteKey sets the site key sent to hCaptcha / CaptchaFox.
func WithSiteKey(key string) Option {
	return func(p *Plugin) { p.config.SiteKey = key }
}

// WithHTTPClient sets the client used for the verification calls.
func WithHTTPClient(c *http.Client) Option {
	return func(p *Plugin) { p.config.HTTPClient = c }
}

// New creates the captcha plugin.
func New(cfg config.CaptchaConfig, opts ...Option) *Plugin {
	p := &Plugin{config: cfg}
	for _, opt := range opts {
		opt(p)
	}
	p.config = p.config.WithDefaults()
	return p
}

// ID returns "captcha".
func (p *Plugin) ID() string { return PluginID }

// Init builds the verification service with the auth base path and client-IP settings.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	if ictx == nil {
		return errors.New("captcha: init context is required")
	}
	// Step 1: the client IP sent to the provider follows Advanced.IPAddress like the rate limiter
	conf := ictx.Config
	clientIP := func(r *http.Request) string {
		ip := humaadapter.ClientIP(conf, r)
		if ip == "" {
			return ""
		}
		return ratelimit.NormalizeIP(ip, conf.Advanced.IPAddress.IPv6Subnet)
	}
	// Step 2: the service matching request paths against the base path
	p.service = services.New(p.config, conf.BasePath, clientIP)
	return nil
}

// RequestHooks returns the captcha check (better-auth's onRequest).
func (p *Plugin) RequestHooks() []endpointhooks.RequestFunc {
	if p.service == nil {
		return nil
	}
	return []endpointhooks.RequestFunc{p.service.OnRequest}
}

// Migrator returns nil: the plugin has no tables.
func (p *Plugin) Migrator() migration.IMigrator { return nil }

// Services exposes the verification service.
func (p *Plugin) Services() map[string]any { return map[string]any{"captcha": p.service} }

// Routes returns nil: the plugin has no endpoints.
func (p *Plugin) Routes() []plugins.RouteDescriptor { return nil }

// Service returns the verification service (nil before Init).
func (p *Plugin) Service() *services.Service { return p.service }

// Config returns the effective configuration.
func (p *Plugin) Config() config.CaptchaConfig { return p.config }
