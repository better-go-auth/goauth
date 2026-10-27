package org

import (
	"fmt"
	"net/http"

	"gorm.io/gorm"

	serv_interfaces "github.com/better-go-auth/goauth/src/app/services/interfaces"
	authconf "github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/migration"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	humaorg "github.com/better-go-auth/goauth/src/plugins/org/adapters/huma"
	"github.com/better-go-auth/goauth/src/plugins/org/config"
	orgmiddleware "github.com/better-go-auth/goauth/src/plugins/org/middleware"
	orgrepo "github.com/better-go-auth/goauth/src/plugins/org/repository"
	gormorg "github.com/better-go-auth/goauth/src/plugins/org/repository/gorm"
	orgsvc "github.com/better-go-auth/goauth/src/plugins/org/services"
	"github.com/better-go-auth/goauth/src/providers/authenticator"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
	"github.com/danielgtaylor/huma/v2"
)

const PluginID = "org"

// OrgPlugin implements the plugins.OrgPlugin interface for multi-tenancy / organizations.
type OrgPlugin struct {
	Config     config.OrgConfig
	authConfig authconf.AuthConfig
	orgRepos   orgrepo.OrgRepositories
	migrator   migration.IMigrator
	// org related service
	service       orgsvc.IOrgService
	hookService   *orgsvc.OrgHookService
	handler       *humaorg.OrgHandler
	authenticator authenticator.AuthenticateFunc
	secStorage    sec_storage.SecondaryStorage
	middleware    *orgmiddleware.OrgAuthMiddleware
}

type Option func(*OrgPlugin)

func WithSecondaryStorage(storage sec_storage.SecondaryStorage) Option {
	return func(p *OrgPlugin) {
		p.secStorage = storage
	}
}

// NewWithGorm creates a new Org plugin directly backed by GORM.
func NewWithGorm(db *gorm.DB, cfg config.OrgConfig, opts ...Option) (*OrgPlugin, error) {
	repos := gormorg.NewOrgRepos(db)
	orgOptions := OrgOptions{
		Repo:   repos,
		Config: cfg,
	}
	return New(orgOptions, opts...)
}

type OrgOptions struct {
	Repo   orgrepo.OrgRepositories
	Config config.OrgConfig
}

// New creates a new Org plugin instance with optional configuration.
func New(options OrgOptions, opts ...Option) (*OrgPlugin, error) {
	p := &OrgPlugin{orgRepos: options.Repo, Config: options.Config}

	for _, opt := range opts {
		opt(p)
	}

	// Step 1: Ensure core repositories and migrator are provided
	if p.orgRepos.IOrgRepo == nil || p.orgRepos.IMemberRepo == nil || p.orgRepos.IInvitationRepo == nil || p.orgRepos.IMigrator == nil {
		return nil, fmt.Errorf("org plugin: OrgRepo, MemberRepo, InviteRepo and Migrator are required")
	}

	// Step 2: Ensure team repositories are provided when teams feature is enabled
	if p.Config.Teams != nil && p.Config.Teams.Enabled {
		if p.orgRepos.ITeamRepo == nil || p.orgRepos.ITeamMemberRepo == nil {
			return nil, fmt.Errorf("org plugin: TeamRepo and TeamMemberRepo are required when teams are enabled")
		}
	}

	// Step 3: Ensure organization role repository is provided when dynamic access control is enabled
	if p.Config.DynamicAccessControl != nil && p.Config.DynamicAccessControl.Enabled {
		if p.orgRepos.IOrganizationRoleRepo == nil {
			return nil, fmt.Errorf("org plugin: OrganizationRoleRepo is required when dynamic access control is enabled")
		}
	}

	p.migrator = p.orgRepos.IMigrator
	return p, nil
}

func WithOrgConfig(orgConfig config.OrgConfig) Option {
	return func(p *OrgPlugin) {
		p.Config = orgConfig
	}
}

func (p *OrgPlugin) ID() string {
	return PluginID
}

func (p *OrgPlugin) Init(ictx *plugin.InitContext) error {
	// 2. Resolve Migrator
	p.migrator = p.orgRepos.IMigrator

	var sessionServ serv_interfaces.ISessionManager
	if ictx != nil {
		sessionServ = ictx.SessionManager
	}

	// 3. Create Org Service
	svc := orgsvc.New(
		p.orgRepos.IOrgRepo,
		p.orgRepos.IMemberRepo,
		p.orgRepos.IInvitationRepo,
		ictx.TxManager,
		ictx.IAuthRepos,
		sessionServ,
	)
	svc.Config = p.Config
	svc.SetRepositories(p.orgRepos)
	if p.secStorage != nil {
		svc.SetSecondaryStorage(p.secStorage)
	} else if ictx != nil && ictx.SecondaryStorage != nil {
		svc.SetSecondaryStorage(ictx.SecondaryStorage)
	}

	p.service = svc
	p.middleware = orgmiddleware.New(p.service)

	p.hookService = orgsvc.NewOrgHookService(p.orgRepos.IOrgRepo, p.orgRepos.IMemberRepo)

	if ictx != nil {
		p.authConfig = ictx.Config
		p.authenticator = ictx.Authenticator
		if ictx.Hooks != nil {
			ictx.Hooks.Register(p.hookService)
		}
	}

	if ictx != nil && ictx.Api != nil {
		p.SetupHumaRoutes(ictx.Api, ictx.MiddleWare)
	}

	return nil
}

func (p *OrgPlugin) Migrator() migration.IMigrator {
	return p.migrator
}

func (p *OrgPlugin) Services() map[string]any {
	return map[string]any{
		"org": p.service,
	}
}

// Hooks returns the HookService implemented by the org plugin.
func (p *OrgPlugin) Hooks() plugin.HookService {
	return p.hookService
}

// Routes returns nil for the org plugin. Routes are currently registered via
// framework-specific helpers (e.g. SetupHumaRoutes, SetupGinRoutes).
// Migrating to RouteDescriptors is tracked in _docs/plugins/authoring-guide.md.
func (p *OrgPlugin) Routes() []plugin.RouteDescriptor {
	return nil
}

// Service returns the initialized IOrgService interface.
func (p *OrgPlugin) Service() orgsvc.IOrgService {
	return p.service
}

// Handler returns the initialized OrgHandler.
func (p *OrgPlugin) Handler() *humaorg.OrgHandler {
	return p.handler
}

// Middleware returns the initialized OrgAuthMiddleware for dynamic RBAC authorization.
func (p *OrgPlugin) Middleware() *orgmiddleware.OrgAuthMiddleware {
	if p.middleware == nil && p.service != nil {
		p.middleware = orgmiddleware.New(p.service)
	}
	return p.middleware
}

// Authorize returns a Huma middleware verifying authorization based on AuthOptions.
func (p *OrgPlugin) Authorize(opts orgmiddleware.AuthOptions) func(huma.Context, func(huma.Context)) {
	return p.Middleware().Authorize(opts)
}

// RequirePermission returns a Huma middleware checking resource and action permissions (e.g. "project", "read").
func (p *OrgPlugin) RequirePermission(resource, action string) func(huma.Context, func(huma.Context)) {
	return p.Middleware().RequirePermission(resource, action)
}

// RequireOperation returns a Huma middleware checking if the operation ID exists in the role's Ops array.
func (p *OrgPlugin) RequireOperation(operationID string) func(huma.Context, func(huma.Context)) {
	return p.Middleware().RequireOperation(operationID)
}

// HTTPAuthorize returns a standard net/http middleware verifying authorization based on AuthOptions.
func (p *OrgPlugin) HTTPAuthorize(opts orgmiddleware.AuthOptions) func(http.Handler) http.Handler {
	return p.Middleware().HTTPAuthorize(opts)
}

// HTTPRequirePermission returns a standard net/http middleware checking resource and action permissions.
func (p *OrgPlugin) HTTPRequirePermission(resource, action string) func(http.Handler) http.Handler {
	return p.Middleware().HTTPRequirePermission(resource, action)
}

// HTTPRequireOperation returns a standard net/http middleware checking operation ID.
func (p *OrgPlugin) HTTPRequireOperation(operationID string) func(http.Handler) http.Handler {
	return p.Middleware().HTTPRequireOperation(operationID)
}
