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
	"github.com/better-go-auth/goauth/src/plugins/org/repository/adapterorg"
	orgsvc "github.com/better-go-auth/goauth/src/plugins/org/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/providers/access"
	"github.com/better-go-auth/goauth/src/providers/authenticator"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
	"github.com/danielgtaylor/huma/v2"
)

const PluginID = "org"

// OrgPlugin implements plugin.Plugin and plugin.SchemaProvider for multi-tenancy / organizations.
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

var (
	_ plugin.Plugin         = (*OrgPlugin)(nil)
	_ plugin.SchemaProvider = (*OrgPlugin)(nil)
)

type Option func(*OrgPlugin)

func WithSecondaryStorage(storage sec_storage.SecondaryStorage) Option {
	return func(p *OrgPlugin) {
		p.secStorage = storage
	}
}

// WithAccessControl sets better-auth's organization `ac` option (switches to better-auth permission semantics).
func WithAccessControl(ac *access.AccessControl) Option {
	return func(p *OrgPlugin) {
		p.Config.AccessControl = ac
	}
}

// WithRoles sets better-auth's organization `roles` option (switches to better-auth permission semantics).
func WithRoles(roles map[string]access.Role) Option {
	return func(p *OrgPlugin) {
		p.Config.AccessRoles = roles
	}
}

// NewWithGorm creates the Org plugin. db is not used: the organization tables are declared with Schema
// and stored through goauth's storage adapter (GoAuthOptions.Conn or adapter-based Repositories).
//
// Deprecated: use New(OrgOptions{Config: cfg}, opts...). NewWithGorm is removed in the next release.
func NewWithGorm(_ *gorm.DB, cfg config.OrgConfig, opts ...Option) (*OrgPlugin, error) {
	return New(OrgOptions{Config: cfg}, opts...)
}

// OrgOptions configures New.
type OrgOptions struct {
	// Repo replaces the default repositories (the organization tables through InitContext.Adapter). Leave
	// it empty to use the defaults; when set, OrgRepo, MemberRepo and InviteRepo are required (plus the team
	// and role repositories when those features are enabled), and its IMigrator, if any, runs in
	// GoAuth.Migrations.Mode auto.
	Repo   orgrepo.OrgRepositories
	Config config.OrgConfig
}

// New creates a new Org plugin instance with optional configuration.
func New(options OrgOptions, opts ...Option) (*OrgPlugin, error) {
	p := &OrgPlugin{orgRepos: options.Repo, Config: options.Config}

	for _, opt := range opts {
		opt(p)
	}

	// Step 1: custom repositories must be complete (the defaults are built in Init from the adapter)
	if p.hasCustomRepos() {
		if err := p.checkRepos(); err != nil {
			return nil, err
		}
	}
	p.migrator = p.orgRepos.IMigrator
	return p, nil
}

// hasCustomRepos reports whether OrgOptions.Repo set any repository.
func (p *OrgPlugin) hasCustomRepos() bool {
	r := p.orgRepos
	return r.IOrgRepo != nil || r.IMemberRepo != nil || r.IInvitationRepo != nil || r.ITeamRepo != nil ||
		r.ITeamMemberRepo != nil || r.IOrganizationRoleRepo != nil
}

// checkRepos ensures the repositories the configured features need are present.
func (p *OrgPlugin) checkRepos() error {
	// Step 1: core repositories
	if p.orgRepos.IOrgRepo == nil || p.orgRepos.IMemberRepo == nil || p.orgRepos.IInvitationRepo == nil {
		return fmt.Errorf("org plugin: OrgRepo, MemberRepo and InviteRepo are required")
	}
	// Step 2: team repositories when the teams feature is enabled
	if p.teamsEnabled() && (p.orgRepos.ITeamRepo == nil || p.orgRepos.ITeamMemberRepo == nil) {
		return fmt.Errorf("org plugin: TeamRepo and TeamMemberRepo are required when teams are enabled")
	}
	// Step 3: organization role repository when dynamic access control is enabled
	if p.dynamicACEnabled() && p.orgRepos.IOrganizationRoleRepo == nil {
		return fmt.Errorf("org plugin: OrganizationRoleRepo is required when dynamic access control is enabled")
	}
	return nil
}

func (p *OrgPlugin) teamsEnabled() bool { return p.Config.Teams != nil && p.Config.Teams.Enabled }

func (p *OrgPlugin) dynamicACEnabled() bool {
	return p.Config.DynamicAccessControl != nil && p.Config.DynamicAccessControl.Enabled
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
	if ictx == nil {
		return fmt.Errorf("org plugin: init context is required")
	}
	// 1. Default repositories: the organization tables (Schema) through the storage adapter
	if !p.hasCustomRepos() {
		if ictx.Adapter == nil {
			return fmt.Errorf("org plugin: a storage adapter (GoAuthOptions.Conn or adapter-based Repositories) or OrgOptions.Repo is required")
		}
		repos, err := adapterorg.NewRepos(ictx.Adapter, ictx.Schema)
		if err != nil {
			return fmt.Errorf("org plugin: %w", err)
		}
		p.orgRepos = repos
		if err := p.checkRepos(); err != nil {
			return err
		}
	}

	// 2. Resolve Migrator (custom repositories only; the default tables come from Schema)
	p.migrator = p.orgRepos.IMigrator

	var sessionServ serv_interfaces.ISessionManager
	if ictx != nil {
		sessionServ = ictx.SessionManager
	}

	// 3. Create Org Service (transactions: GoAuthOptions.TxManager, else the adapter's)
	svc := orgsvc.New(
		p.orgRepos.IOrgRepo,
		p.orgRepos.IMemberRepo,
		p.orgRepos.IInvitationRepo,
		pluginkit.TxManager(ictx.TxManager, ictx.Adapter),
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

	p.hookService = orgsvc.NewOrgHookService(p.orgRepos.IOrgRepo, p.orgRepos.IMemberRepo).
		WithUserCleanup(p.orgRepos.IInvitationRepo, p.orgRepos.ITeamMemberRepo)

	if ictx != nil {
		p.authConfig = ictx.Config
		p.authenticator = ictx.Authenticator
		if ictx.Hooks != nil {
			ictx.Hooks.Register(p.hookService)
		}
	}

	// 4. HTTP endpoints through pluginkit (one session resolver, origin check, disabled routes, rate limit)
	if ictx.Api != nil {
		kit, err := pluginkit.New(ictx)
		if err != nil {
			return fmt.Errorf("org plugin: %w", err)
		}
		p.SetupHumaRoutes(ictx.Api, kit)
	}

	return nil
}

// Migrator returns the migrator of custom repositories (OrgOptions.Repo.IMigrator), else nil: the default
// tables are declared by Schema and created by goauth's migrator.
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

// Repositories returns the plugin's repositories (OrgOptions.Repo, else the defaults on the storage adapter,
// available after Init), e.g. for a Teams.DefaultTeam.CustomCreateDefaultTeam callback that stores a team.
func (p *OrgPlugin) Repositories() orgrepo.OrgRepositories {
	return p.orgRepos
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
