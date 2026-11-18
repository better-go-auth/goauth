// Package username ports better-auth's username plugin: sign-in with username + password, username
// availability checks, and username / displayUsername on sign-up and update-user.
//
// The username / displayUsername columns live on the core user table, so the plugin has no migrator.
// Sign-up and update-user fields are handled through the core UserInput hook (plugins.UserInputEvent).
package username

import (
	"context"
	"errors"

	authsvc "github.com/better-go-auth/goauth/src/app/services/auth"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	humausername "github.com/better-go-auth/goauth/src/plugins/username/adapters/huma"
	"github.com/better-go-auth/goauth/src/plugins/username/config"
	"github.com/better-go-auth/goauth/src/plugins/username/services"
)

// PluginID is better-auth's plugin id.
const PluginID = "username"

// ErrorCodes are better-auth's USERNAME_ERROR_CODES.
var ErrorCodes = services.ErrorCodes

// Plugin implements plugins.Plugin for better-auth's username plugin.
type Plugin struct {
	config  config.UsernameConfig
	kit     *pluginkit.Kit
	service *services.Service
	handler *humausername.Handler
}

var _ plugins.Plugin = (*Plugin)(nil)

// Option configures the plugin.
type Option func(*Plugin)

// WithMinUsernameLength sets the minimum username length (default 3).
func WithMinUsernameLength(n int) Option { return func(p *Plugin) { p.config.MinUsernameLength = n } }

// WithMaxUsernameLength sets the maximum username length (default 30).
func WithMaxUsernameLength(n int) Option { return func(p *Plugin) { p.config.MaxUsernameLength = n } }

// WithUsernameValidator replaces the default username format check.
func WithUsernameValidator(fn config.ValidatorFunc) Option {
	return func(p *Plugin) { p.config.UsernameValidator = fn }
}

// WithDisplayUsernameValidator sets the display username check.
func WithDisplayUsernameValidator(fn config.ValidatorFunc) Option {
	return func(p *Plugin) { p.config.DisplayUsernameValidator = fn }
}

// WithUsernameNormalization replaces the default lowercase normalization.
func WithUsernameNormalization(fn config.NormalizerFunc) Option {
	return func(p *Plugin) { p.config.UsernameNormalization = fn }
}

// WithoutUsernameNormalization stores usernames as sent (better-auth's usernameNormalization: false).
func WithoutUsernameNormalization() Option {
	return func(p *Plugin) { p.config.DisableUsernameNormalization = true }
}

// WithDisplayUsernameNormalization sets the display username normalization.
func WithDisplayUsernameNormalization(fn config.NormalizerFunc) Option {
	return func(p *Plugin) { p.config.DisplayUsernameNormalization = fn }
}

// WithValidationOrder selects whether validators see raw or normalized values.
func WithValidationOrder(order config.ValidationOrder) Option {
	return func(p *Plugin) { p.config.ValidationOrder = order }
}

// New creates the username plugin.
func New(cfg config.UsernameConfig, opts ...Option) *Plugin {
	p := &Plugin{config: cfg}
	for _, opt := range opts {
		opt(p)
	}
	p.config = p.config.WithDefaults()
	return p
}

// ID returns "username".
func (p *Plugin) ID() string { return PluginID }

// Init builds the service, registers the user hooks and mounts the endpoints.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	if ictx == nil {
		return errors.New("username: init context is required")
	}
	// Step 1: shared plugin runtime (sessions, cookies, origin check, rate limiter)
	kit, err := pluginkit.New(ictx)
	if err != nil {
		return err
	}
	p.kit = kit
	// Step 2: service (the core auth service re-sends verification emails on sign-in)
	verifier, _ := ictx.IAuthSvc.(authsvc.VerificationSender)
	p.service = services.NewService(p.config, kit, verifier)
	// Step 3: sign-up / update-user fields and better-auth's user create database hook
	if ictx.Hooks != nil {
		ictx.Hooks.OnUserInput(p.service.OnUserInput)
		ictx.Hooks.OnBeforeUserCreate(func(ctx context.Context, user *models.User) error {
			return p.service.BeforeUserCreate(ctx, user)
		})
	}
	// Step 4: mount the routes
	p.handler = humausername.NewHandler(p.service)
	humausername.RegisterRoutes(ictx.Api, kit, p.handler)
	return nil
}

// Migrator returns nil: the plugin's columns are part of the core user table.
func (p *Plugin) Migrator() migration.IMigrator { return nil }

// Services exposes the plugin service.
func (p *Plugin) Services() map[string]any { return map[string]any{"username": p.service} }

// Routes returns nil: routes are mounted on Huma in Init.
func (p *Plugin) Routes() []plugins.RouteDescriptor { return nil }

// Service returns the plugin service (nil before Init).
func (p *Plugin) Service() *services.Service { return p.service }

// Config returns the effective configuration.
func (p *Plugin) Config() config.UsernameConfig { return p.config }

// SchemaFields implements plugins.SchemaFieldsProvider (username plugin: username and displayUsername on the user).
func (p *Plugin) SchemaFields() dtos.SchemaFields {
	return dtos.SchemaFields{User: []string{dtos.FieldUsername, dtos.FieldDisplayUsername}}
}
