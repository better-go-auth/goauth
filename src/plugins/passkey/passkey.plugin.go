// Package passkey ports better-auth's passkey (WebAuthn) plugin (@better-auth/passkey 1.6.16).
package passkey

import (
	"context"
	"fmt"

	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	humapasskey "github.com/better-go-auth/goauth/src/plugins/passkey/adapters/huma"
	pkconfig "github.com/better-go-auth/goauth/src/plugins/passkey/config"
	"github.com/better-go-auth/goauth/src/plugins/passkey/repository"
	"github.com/better-go-auth/goauth/src/plugins/passkey/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

// PluginID is better-auth's plugin id.
const PluginID = "passkey"

// Plugin implements plugins.Plugin and plugins.HookProvider for passkeys.
type Plugin struct {
	config      pkconfig.PasskeyConfig
	repo        repository.IPasskeyRepo
	service     *services.PasskeyService
	handler     *humapasskey.Handler
	hookService *passkeyHookService
}

var (
	_ plugins.Plugin       = (*Plugin)(nil)
	_ plugins.HookProvider = (*Plugin)(nil)
)

// Option configures the passkey plugin.
type Option func(*Plugin)

// WithRPID sets the relying party ID.
func WithRPID(rpID string) Option { return func(p *Plugin) { p.config.RPID = rpID } }

// WithRPName sets the relying party name.
func WithRPName(name string) Option { return func(p *Plugin) { p.config.RPName = name } }

// WithOrigin sets the expected origin(s) of WebAuthn responses.
func WithOrigin(origins ...string) Option {
	return func(p *Plugin) { p.config.Origin = append([]string(nil), origins...) }
}

// WithAuthenticatorSelection overrides the registration authenticator selection.
func WithAuthenticatorSelection(sel pkconfig.AuthenticatorSelection) Option {
	return func(p *Plugin) { p.config.AuthenticatorSelection = &sel }
}

// WithRepository replaces the GORM passkey repository.
func WithRepository(repo repository.IPasskeyRepo) Option { return func(p *Plugin) { p.repo = repo } }

// New creates the passkey plugin.
func New(cfg pkconfig.PasskeyConfig, opts ...Option) *Plugin {
	// Step 1: copy the config and apply the functional options
	p := &Plugin{config: cfg}
	for _, opt := range opts {
		opt(p)
	}
	// Step 2: defaults
	if p.config.Advanced.WebAuthnChallengeCookie == "" {
		p.config.Advanced.WebAuthnChallengeCookie = pkconfig.DefaultWebAuthnChallengeCookie
	}
	p.hookService = &passkeyHookService{plugin: p}
	return p
}

// ID returns "passkey".
func (p *Plugin) ID() string { return PluginID }

// Init builds the repository, the service and mounts the routes.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	// Step 1: shared plugin runtime (cookies, sessions, origin checks)
	kit, err := pluginkit.New(ictx)
	if err != nil {
		return fmt.Errorf("passkey plugin: %w", err)
	}
	// Step 2: storage
	if p.repo == nil {
		if ictx.DB == nil {
			return fmt.Errorf("passkey plugin: a *gorm.DB is required")
		}
		p.repo = repository.NewGormPasskeyRepo(ictx.DB)
	}
	// Step 3: service and routes
	p.service = services.NewPasskeyService(p.config, kit, p.repo)
	p.handler = humapasskey.NewHandler(p.service, kit)
	humapasskey.SetupRoutes(ictx.Api, kit, p.handler, p.config.RequireSession())
	return nil
}

// Migrator creates the passkey table.
func (p *Plugin) Migrator() migration.IMigrator {
	if p.repo == nil {
		return nil
	}
	return p.repo.Migrator()
}

// Services exposes the passkey service.
func (p *Plugin) Services() map[string]any { return map[string]any{"passkey": p.service} }

// Routes returns nil: routes are mounted on Huma in Init.
func (p *Plugin) Routes() []plugins.RouteDescriptor { return nil }

// Hooks returns the lifecycle hooks (passkey cleanup on user deletion).
func (p *Plugin) Hooks() plugins.HookService { return p.hookService }

// Service returns the passkey service (nil before Init).
func (p *Plugin) Service() *services.PasskeyService { return p.service }

type passkeyHookService struct {
	plugins.DefaultHookService
	plugin *Plugin
}

// UserDeleted removes the deleted user's passkeys.
func (h *passkeyHookService) UserDeleted(ctx context.Context, userID string) error {
	if h.plugin.service == nil {
		return nil
	}
	return h.plugin.service.DeleteUserPasskeys(ctx, userID)
}
