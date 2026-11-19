// Package phonenumber ports better-auth's phone-number plugin: SMS OTP verification and sign-up,
// phone number + password sign-in and password reset by SMS.
//
// The phoneNumber / phoneNumberVerified columns live on the core user table, so the plugin has no migrator.
package phonenumber

import (
	"context"
	"errors"
	"time"

	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	humaphone "github.com/better-go-auth/goauth/src/plugins/phone-number/adapters/huma"
	"github.com/better-go-auth/goauth/src/plugins/phone-number/config"
	"github.com/better-go-auth/goauth/src/plugins/phone-number/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/providers/ratelimit"
)

// PluginID is better-auth's plugin id.
const PluginID = "phone-number"

// ErrorCodes are better-auth's PHONE_NUMBER_ERROR_CODES.
var ErrorCodes = services.ErrorCodes

// Plugin implements plugins.Plugin for better-auth's phone-number plugin.
type Plugin struct {
	config  config.PhoneNumberConfig
	kit     *pluginkit.Kit
	service *services.PhoneNumberService
	handler *humaphone.Handler
}

var (
	_ plugins.Plugin            = (*Plugin)(nil)
	_ plugins.RateLimitProvider = (*Plugin)(nil)
)

// RateLimitRules is better-auth's phone-number rule: paths starting with /phone-number, 10 requests per 60 s.
func (p *Plugin) RateLimitRules() []ratelimit.PathRule { return humaphone.RateLimitRules() }

// Option configures the plugin.
type Option func(*Plugin)

// WithSendOTP sets the SMS sender of verification codes.
func WithSendOTP(fn config.SendOTPFunc) Option {
	return func(p *Plugin) { p.config.SendOTP = fn }
}

// WithSendPasswordResetOTP sets the SMS sender of password reset codes.
func WithSendPasswordResetOTP(fn config.SendOTPFunc) Option {
	return func(p *Plugin) { p.config.SendPasswordResetOTP = fn }
}

// WithVerifyOTP replaces the built-in code check.
func WithVerifyOTP(fn config.VerifyOTPFunc) Option {
	return func(p *Plugin) { p.config.VerifyOTP = fn }
}

// WithPhoneNumberValidator sets the phone number format check.
func WithPhoneNumberValidator(fn config.PhoneNumberValidatorFunc) Option {
	return func(p *Plugin) { p.config.PhoneNumberValidator = fn }
}

// WithOTPLength sets the number of code digits (default 6).
func WithOTPLength(n int) Option {
	return func(p *Plugin) { p.config.OTPLength = n }
}

// WithExpiresIn sets the code lifetime (default 300s).
func WithExpiresIn(d time.Duration) Option {
	return func(p *Plugin) { p.config.ExpiresIn = d }
}

// WithAllowedAttempts sets how many wrong codes are accepted (default 3).
func WithAllowedAttempts(n int) Option {
	return func(p *Plugin) { p.config.AllowedAttempts = n }
}

// WithRequireVerification blocks password sign-in for unverified numbers.
func WithRequireVerification(require bool) Option {
	return func(p *Plugin) { p.config.RequireVerification = require }
}

// WithSignUpOnVerification creates users for unknown numbers on verification.
func WithSignUpOnVerification(opts config.SignUpOnVerification) Option {
	return func(p *Plugin) { p.config.SignUpOnVerification = &opts }
}

// WithCallbackOnVerification runs fn after each successful verification.
func WithCallbackOnVerification(fn config.CallbackOnVerificationFunc) Option {
	return func(p *Plugin) { p.config.CallbackOnVerification = fn }
}

// New creates the phone-number plugin.
func New(cfg config.PhoneNumberConfig, opts ...Option) *Plugin {
	p := &Plugin{config: cfg}
	for _, opt := range opts {
		opt(p)
	}
	p.config = p.config.WithDefaults()
	return p
}

// ID returns "phone-number".
func (p *Plugin) ID() string { return PluginID }

// Init builds the service and mounts the endpoints.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	if ictx == nil {
		return errors.New("phone-number: init context is required")
	}
	// better-auth's signUpOnVerification requires getTempEmail (there is no fallback email)
	if p.config.SignUpOnVerification != nil && p.config.SignUpOnVerification.GetTempEmail == nil {
		return errors.New("phone-number: SignUpOnVerification.GetTempEmail is required (better-auth's signUpOnVerification.getTempEmail)")
	}
	// Step 1: shared plugin runtime (sessions, cookies, origin check, rate limiter)
	kit, err := pluginkit.New(ictx)
	if err != nil {
		return err
	}
	p.kit = kit
	// Step 2: service and HTTP handler
	p.service = services.NewPhoneNumberService(p.config, kit)
	p.handler = humaphone.NewHandler(p.service)
	// Step 3: mount the routes
	humaphone.RegisterRoutes(ictx.Api, kit, p.handler)
	// better-auth's before hook on /update-user: the number only changes through OTP verification; only
	// null (clearing it) is accepted (`"phoneNumber" in body && body.phoneNumber !== null` throws)
	if ictx.Hooks != nil {
		ictx.Hooks.OnUserInput(func(_ context.Context, ev *plugins.UserInputEvent) error {
			if v, sent := ev.Body["phoneNumber"]; ev.Path == plugins.UserInputUpdateUser && sent && v != nil {
				return services.ErrPhoneNumberCannotBeUpdated
			}
			return nil
		})
	}
	return nil
}

// Migrator returns nil: the plugin's columns are part of the core user table.
func (p *Plugin) Migrator() migration.IMigrator { return nil }

// Services exposes the plugin service.
func (p *Plugin) Services() map[string]any {
	return map[string]any{"phoneNumber": p.service}
}

// Routes returns nil: routes are mounted on Huma in Init.
func (p *Plugin) Routes() []plugins.RouteDescriptor { return nil }

// Service returns the plugin service (nil before Init).
func (p *Plugin) Service() *services.PhoneNumberService { return p.service }

// Config returns the effective configuration.
func (p *Plugin) Config() config.PhoneNumberConfig { return p.config }
