package admin

import (
	"fmt"
	"strings"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/enums"
	"github.com/better-go-auth/goauth/src/models/migration"
	plugins "github.com/better-go-auth/goauth/src/plugins"
	humaadmin "github.com/better-go-auth/goauth/src/plugins/admin/adapters/huma"
	config1 "github.com/better-go-auth/goauth/src/plugins/admin/config"
	"github.com/better-go-auth/goauth/src/plugins/admin/repository"
	gormadmin "github.com/better-go-auth/goauth/src/plugins/admin/repository/gorm"
	adminsvc "github.com/better-go-auth/goauth/src/plugins/admin/services"
	"github.com/better-go-auth/goauth/src/providers/access"
	"github.com/better-go-auth/goauth/src/providers/authenticator"
	"gorm.io/gorm"
)

const PluginID = "admin"

// Plugin implements the plugins.Plugin interface for the Better Auth Admin plugin.
type Plugin struct {
	adminRepos   repository.AdminRepositories
	config       config1.AdminConfig
	migrator     migration.IMigrator
	service      adminsvc.IAdminService
	hookService  *adminsvc.AdminHookService
	sessionConf  config.SessionGoAuth
	rootConfig   config.AuthConfig
	basePath     string
	handler      *humaadmin.AdminHandler
	authenticate authenticator.AuthenticateFunc
	// adminRolesSet records an explicit WithAdminRoles call (validated against custom roles)
	adminRolesSet bool
}

// Option configures the admin Plugin.
type Option func(*Plugin)

// WithAdminRoles specifies the roles permitted to access admin operations.
func WithAdminRoles(roles ...enums.Role) Option {
	return func(p *Plugin) {
		if len(roles) > 0 {
			p.config.AdminRoles = roles
			p.adminRolesSet = true
		}
	}
}

// WithAccessControl sets better-auth's `ac` option: the statements custom roles are built from.
func WithAccessControl(ac *access.AccessControl) Option {
	return func(p *Plugin) {
		p.config.AccessControl = ac
	}
}

// WithRoles sets better-auth's `roles` option. Once set, permission checks use exactly these
// roles (better-auth semantics) instead of the default admin/user roles.
func WithRoles(roles map[string]access.Role) Option {
	return func(p *Plugin) {
		p.config.Roles = access.Roles(roles)
	}
}

// WithAdminUserIDs sets better-auth's `adminUserIds`: users that pass every admin permission check.
func WithAdminUserIDs(ids ...string) Option {
	return func(p *Plugin) {
		p.config.AdminUserIDs = append(p.config.AdminUserIDs, ids...)
	}
}

// WithAllowImpersonatingAdmins sets better-auth's `allowImpersonatingAdmins`.
func WithAllowImpersonatingAdmins(allow bool) Option {
	return func(p *Plugin) {
		p.config.AllowImpersonatingAdmins = allow
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
//
//	func WithJwtSecret(secret string) Option {
//		return func(p *Plugin) {
//			p.jwtSecret = secret
//		}
//	}
func WithSessionConfig(sessionConfig config.SessionGoAuth) Option {
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

// NewWithGorm creates a new Admin plugin directly backed by GORM.
func NewWithGorm(db *gorm.DB, opts ...Option) (*Plugin, error) {
	repos := gormadmin.NewAdminGormRepos(db)
	return New(repos, opts...)
}

// New creates a new Admin plugin with the provided repository bundle and options.
func New(repos repository.AdminRepositories, opts ...Option) (*Plugin, error) {
	p := &Plugin{
		adminRepos: repos,
		config:     config1.DefaultAdminConfig(),
	}
	for _, opt := range opts {
		opt(p)
	}
	if p.adminRepos.AdminRepo == nil || p.adminRepos.Migrator == nil {
		return nil, fmt.Errorf("admin plugin: AdminRepo and Migrator are required")
	}
	// Like better-auth, explicitly configured admin roles must exist in the custom roles.
	if p.adminRolesSet && p.config.CustomRoles() {
		var invalid []string
		for _, r := range p.config.AdminRoles {
			found := false
			for name := range p.config.Roles {
				if strings.EqualFold(name, r.S()) {
					found = true
					break
				}
			}
			if !found {
				invalid = append(invalid, r.S())
			}
		}
		if len(invalid) > 0 {
			return nil, fmt.Errorf("admin plugin: invalid admin roles: %s. Admin roles must be defined in the 'roles' configuration", strings.Join(invalid, ", "))
		}
	}
	p.migrator = p.adminRepos.Migrator
	return p, nil
}

func (p *Plugin) ID() string {
	return PluginID
}

func (p *Plugin) Init(ictx *plugins.InitContext) error {
	if p.adminRepos.AdminRepo == nil {
		return fmt.Errorf("admin plugin: AdminRepo is required")
	}

	svc := adminsvc.NewAdminService(
		p.adminRepos.AdminRepo,
		p.config,
	)
	p.service = svc

	p.hookService = adminsvc.NewAdminHookService(p.adminRepos.AdminRepo)

	if ictx != nil {
		p.rootConfig = ictx.Config
		p.authenticate = ictx.Authenticator
		svc.SetAuthConfig(ictx.Config)

		svc.SetSessionService(ictx.SessionManager)

		if ictx.Hooks != nil {
			ictx.Hooks.Register(p.hookService)
			p.service.SetHooks(ictx.Hooks)
		}
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
	return map[string]interface{}{
		"admin": p.service,
	}
}

// Hooks returns the HookService implemented by the admin plugin.
func (p *Plugin) Hooks() plugins.HookService {
	return p.hookService
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
func (p *Plugin) Config() config1.AdminConfig {
	return p.config
}
