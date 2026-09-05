package admin

import (
	"fmt"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/enums"
	"github.com/better-go-auth/goauth/src/models/migration"
	plugins "github.com/better-go-auth/goauth/src/plugins"
	humaadmin "github.com/better-go-auth/goauth/src/plugins/admin/adapters/huma"
	"github.com/better-go-auth/goauth/src/plugins/admin/models"
	"github.com/better-go-auth/goauth/src/plugins/admin/repository"
	gormadmin "github.com/better-go-auth/goauth/src/plugins/admin/repository/gorm"
	adminsvc "github.com/better-go-auth/goauth/src/plugins/admin/services"
	"gorm.io/gorm"
)

const PluginID = "admin"

// Plugin implements the plugins.Plugin interface for the Better Auth Admin plugin.
type Plugin struct {
	adminRepos  repository.AdminRepositories
	config      models.AdminConfig
	migrator    migration.IMigrator
	service     adminsvc.IAdminService
	sessionConf config.SessionConfig
	basePath    string
	handler     *humaadmin.AdminHandler
}

// Option configures the admin Plugin.
type Option func(*Plugin)

// WithAdminRoles specifies the roles permitted to access admin operations.
func WithAdminRoles(roles ...enums.Role) Option {
	return func(p *Plugin) {
		if len(roles) > 0 {
			p.config.AdminRoles = roles
		}
	}
}

// WithDefaultRole sets the default role assigned to new users when not explicitly given.
func WithDefaultRole(role enums.Role) Option {
	return func(p *Plugin) {
		if role != "" {
			p.config.DefaultRole = role
		}
	}
}

// WithJwtSecret configures the JWT secret used to authenticate admin tokens.
// func WithJwtSecret(secret string) Option {
// 	return func(p *Plugin) {
// 		p.jwtSecret = secret
// 	}
// }
func WithSessionConfig(sessionConfig config.SessionConfig) Option {
	return func(p *Plugin) {
		p.sessionConf = sessionConfig
	}
}

// WithBasePath configures the base path for admin routes (e.g. "/api/auth" or "/api/v1").
func WithBasePath(basePath string) Option {
	return func(p *Plugin) {
		p.basePath = basePath
	}
}

// New creates a new Admin plugin with the provided repository bundle and options.
func New(repos repository.AdminRepositories, opts ...Option) *Plugin {
	p := &Plugin{
		adminRepos: repos,
		config:     models.DefaultAdminConfig(),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// NewWithGorm creates a new Admin plugin directly backed by GORM.
func NewWithGorm(db *gorm.DB, opts ...Option) *Plugin {
	repos := gormadmin.NewAdminRepos(db)
	return New(repos, opts...)
}

func (p *Plugin) ID() string {
	return PluginID
}

func (p *Plugin) Init(ictx *plugins.InitContext) error {
	if p.adminRepos.AdminRepo == nil {
		return fmt.Errorf("admin plugin: AdminRepo is required")
	}

	p.migrator = p.adminRepos.Migrator

	p.service = adminsvc.NewAdminService(
		p.adminRepos.AdminRepo,
		p.config,
	)


	if ictx != nil && ictx.Api != nil {
		p.SetupHumaRoutes(ictx.Api)
	}

	return nil
}

func (p *Plugin) Migrator() migration.IMigrator {
	return p.migrator
}

func (p *Plugin) Services() map[string]interface{} {
	return map[string]interface{}{
		"admin": p.service,
	}
}

func (p *Plugin) Routes() []plugins.RouteDescriptor {
	return nil
}

// Service returns the initialized IAdminService.
func (p *Plugin) Service() adminsvc.IAdminService {
	return p.service
}

// Handler returns the initialized AdminHandler.
func (p *Plugin) Handler() *humaadmin.AdminHandler {
	return p.handler
}

// Config returns the plugin's configuration.
func (p *Plugin) Config() models.AdminConfig {
	return p.config
}
