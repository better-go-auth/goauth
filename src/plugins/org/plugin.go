package org

import (
	"context"
	"fmt"

	"gorm.io/gorm"

	authconf "github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/migration"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	humaorg "github.com/better-go-auth/goauth/src/plugins/org/adapters/huma"
	"github.com/better-go-auth/goauth/src/plugins/org/config"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
	orgrepo "github.com/better-go-auth/goauth/src/plugins/org/repository"
	gormorg "github.com/better-go-auth/goauth/src/plugins/org/repository/gorm"
	orgsvc "github.com/better-go-auth/goauth/src/plugins/org/services"
)

const PluginID = "org"

// Plugin implements the plugins.Plugin interface for multi-tenancy / organizations.
type Plugin struct {
	Config       config.OrgConfig
	authConfig   authconf.AuthConfig
	orgReops     orgrepo.OrgRepositories
	migrator     migration.IMigrator
	service      orgsvc.IOrgService
	handler      *humaorg.OrgHandler
	authenticate plugin.AuthenticateFunc
}
type Option func(*Plugin)

// NewWithGorm creates a new Admin plugin directly backed by GORM.
func NewWithGorm(db *gorm.DB, cfg config.OrgConfig, opts ...Option) *Plugin {
	repos := gormorg.NewOrgRepos(db)
	orgOptions := OrgOptions{
		repo:   repos,
		config: cfg,
	}
	return New(orgOptions, opts...)
}

type OrgOptions struct {
	repo   orgrepo.OrgRepositories
	config config.OrgConfig
}

// New creates a new Org plugin instance with optional configuration.
func New(options OrgOptions, opts ...Option) *Plugin {
	p := &Plugin{orgReops: options.repo, Config: options.config}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func WithOrgConfig(orgConfig config.OrgConfig) Option {
	return func(p *Plugin) {
		p.Config = orgConfig
	}
}

func (p *Plugin) ID() string {
	return PluginID
}

func (p *Plugin) Init(ictx *plugin.InitContext) error {
	if p.orgReops.IOrgRepo == nil || p.orgReops.IMemberRepo == nil || p.orgReops.IInvitationRepo == nil || p.orgReops.IMigrator == nil {
		return fmt.Errorf("org plugin: OrgRepo, MemberRepo, InviteRepo and Migrator are required")
	}

	// 2. Resolve Migrator
	p.migrator = p.orgReops.IMigrator

	// 3. Create Org Service
	p.service = orgsvc.New(
		p.orgReops.IOrgRepo,
		p.orgReops.IMemberRepo,
		p.orgReops.IInvitationRepo,
		ictx.TxManager,
		ictx.IAuthRepos,
	)

	if ictx != nil {
		p.authConfig = ictx.Config
		p.authenticate = ictx.Authenticate
	}

	if ictx != nil && ictx.Api != nil {
		p.SetupHumaRoutes(ictx.Api, ictx.MiddleWare)
	}

	return nil
}

func (p *Plugin) Migrator() migration.IMigrator {
	return p.migrator
}

func (p *Plugin) Services() map[string]any {
	return map[string]any{
		"org": p.service,
	}
}

// Routes returns nil for the org plugin. Routes are currently registered via
// framework-specific helpers (e.g. SetupHumaRoutes, SetupGinRoutes).
// Migrating to RouteDescriptors is tracked in _docs/plugins/authoring-guide.md.
func (p *Plugin) Routes() []plugin.RouteDescriptor {
	return nil
}

// Service returns the initialized IOrgService interface.
func (p *Plugin) Service() orgsvc.IOrgService {
	return p.service
}

// Handler returns the initialized OrgHandler.
func (p *Plugin) Handler() *humaorg.OrgHandler {
	return p.handler
}

// ─── Org Migrator ─────────────────────────────────────────────────────────────

// GORMOrgMigrator implements IMigrator for Org module models.
type GORMOrgMigrator struct {
	db *gorm.DB
}

// NewGORMOrgMigrator creates a new GORM migrator for Org module models.
func NewGORMOrgMigrator(db *gorm.DB) migration.IMigrator {
	return &GORMOrgMigrator{db: db}
}

// Migrate runs GORM AutoMigrate on Org models (Organization, Member, Invitation, OrgPermission).
func (m *GORMOrgMigrator) Migrate(_ context.Context) error {
	err := m.db.AutoMigrate(
		&models.Organization{},
		&models.Member{},
		&models.Invitation{},
		&models.OrgPermission{},
	)
	if err != nil {
		return fmt.Errorf("gorm/migrate-org: %w", err)
	}
	return nil
}
