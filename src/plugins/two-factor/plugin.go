// Package twofactor is the Go port of better-auth's two-factor plugin: TOTP, email/SMS OTP and backup
// codes as a second factor, with trusted devices.
//
//	twofactor.New(tfconfig.Config{Issuer: "My App", OTPOptions: tfconfig.OTPOptions{SendOTP: send}})
package twofactor

import (
	"context"
	"errors"

	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	humatf "github.com/better-go-auth/goauth/src/plugins/two-factor/adapters/huma"
	tfconfig "github.com/better-go-auth/goauth/src/plugins/two-factor/config"
	"github.com/better-go-auth/goauth/src/plugins/two-factor/repository"
	"github.com/better-go-auth/goauth/src/plugins/two-factor/services"
)

// PluginID is better-auth's plugin id.
const PluginID = "two-factor"

// Plugin implements plugins.Plugin and plugins.HookProvider.
type Plugin struct {
	config  tfconfig.Config
	repo    repository.ITwoFactorRepo
	kit     *pluginkit.Kit
	service *services.Service
	handler *humatf.Handler
	hooks   *hookService
}

var (
	_ plugins.Plugin       = (*Plugin)(nil)
	_ plugins.HookProvider = (*Plugin)(nil)
)

// Option configures the plugin.
type Option func(*Plugin)

// WithRepo sets a custom twoFactor repository (default: GORM on the auth database).
func WithRepo(repo repository.ITwoFactorRepo) Option {
	return func(p *Plugin) { p.repo = repo }
}

// WithIssuer sets the issuer shown in authenticator apps.
func WithIssuer(issuer string) Option {
	return func(p *Plugin) { p.config.Issuer = issuer }
}

// WithSendOTP enables the OTP method.
func WithSendOTP(fn tfconfig.SendOTPFunc) Option {
	return func(p *Plugin) { p.config.OTPOptions.SendOTP = fn }
}

// New creates the plugin. Unset options get better-auth's defaults.
func New(cfg tfconfig.Config, opts ...Option) *Plugin {
	// Step 1: construct and apply the functional options
	p := &Plugin{config: cfg}
	for _, opt := range opts {
		opt(p)
	}
	// Step 2: fill the defaults
	p.config = p.config.WithDefaults()
	return p
}

// ID returns "two-factor".
func (p *Plugin) ID() string { return PluginID }

// Init builds the service, registers the sign-in interceptor and mounts the routes.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	// Step 1: shared plugin runtime (sessions, cookies, repos, rate limiter)
	kit, err := pluginkit.New(ictx)
	if err != nil {
		return err
	}
	p.kit = kit
	// Step 2: twoFactor table repository
	if p.repo == nil {
		if ictx.DB == nil {
			return errors.New("two-factor plugin: a *gorm.DB or WithRepo is required")
		}
		p.repo = repository.NewGormRepo(ictx.DB)
	}
	// Step 3: service, lifecycle hooks and the sign-in challenge
	p.service = services.New(p.config, kit, p.repo)
	p.hooks = &hookService{plugin: p}
	if ictx.Hooks != nil {
		ictx.Hooks.OnAfterSignIn(p.service.AfterSignIn)
	}
	// Step 4: HTTP endpoints
	p.handler = humatf.NewHandler(p.service, kit)
	if ictx.Api != nil {
		humatf.Register(ictx.Api, kit, p.handler)
	}
	return nil
}

// Migrator creates the twoFactor table.
func (p *Plugin) Migrator() migration.IMigrator {
	if p.repo == nil {
		return nil
	}
	return p.repo.Migrator()
}

// Services exposes the two-factor service.
func (p *Plugin) Services() map[string]any {
	return map[string]any{"two_factor": p.service}
}

// Routes returns nil: endpoints are mounted on the Huma API in Init.
func (p *Plugin) Routes() []plugins.RouteDescriptor { return nil }

// Hooks returns the lifecycle hooks (twoFactor rows are deleted with the user).
func (p *Plugin) Hooks() plugins.HookService {
	if p.hooks == nil {
		return nil
	}
	return p.hooks
}

// Service returns the initialised service (nil before Init).
func (p *Plugin) Service() *services.Service { return p.service }

// Config returns the effective configuration.
func (p *Plugin) Config() tfconfig.Config { return p.config }

// GenerateTOTP is better-auth's server-only auth.api.generateTOTP: the current code for a raw secret.
func (p *Plugin) GenerateTOTP(secret string) (string, error) {
	if p.service == nil {
		return "", errors.New("two-factor plugin: not initialised")
	}
	return p.service.GenerateTOTP(secret)
}

// ViewBackupCodes is better-auth's server-only auth.api.viewBackupCodes: the user's remaining backup codes.
func (p *Plugin) ViewBackupCodes(ctx context.Context, userID string) ([]string, error) {
	if p.service == nil {
		return nil, errors.New("two-factor plugin: not initialised")
	}
	return p.service.ViewBackupCodes(ctx, userID)
}

// hookService deletes a user's 2FA rows when the user is deleted.
type hookService struct {
	plugins.DefaultHookService
	plugin *Plugin
}

func (h *hookService) UserDeleted(ctx context.Context, userID string) error {
	if h.plugin.repo == nil {
		return nil
	}
	return h.plugin.repo.DeleteByUserID(ctx, userID)
}
