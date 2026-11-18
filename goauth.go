package goauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	humaadapter "github.com/better-go-auth/goauth/src/app/adapters/huma"
	"github.com/better-go-auth/goauth/src/app/repository/gormauth"
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/app/repository/verifycleanup"
	authsvc "github.com/better-go-auth/goauth/src/app/services/auth"
	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	"github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/models/migration"
	core_migration "github.com/better-go-auth/goauth/src/models/migration/core-migration"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/providers/authenticator"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	"github.com/better-go-auth/goauth/src/providers/idgen"
	"github.com/better-go-auth/goauth/src/providers/origin"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
	"gorm.io/gorm"

	"github.com/better-go-auth/goauth/src/common/middleware"
	"github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/providers"
	"github.com/danielgtaylor/huma/v2"
)

// GoAuth is the fully-initialized auth runtime returned by SetupGoAuth.
// Fields are read-only after SetupGoAuth returns; mutating them is not
// supported and may break middleware, hooks, and session handling.
type GoAuth struct {
	options GoAuthOptions
	plugins map[string]plugin.Plugin
	hooks   plugin.HookRegistry
	// middleware

	middlewareInt      middleware.IAuthMiddleware
	revocationStore    middleware.RevocationStore
	transactionManager interfaces.ITransactionManager
	provider           *providers.IProviderS
	repositories       repo_interfaces.IAuthRepos
	sessions           *sessionsvc.Manager
	auth               *authsvc.Service
	sessionResolver    *humaadapter.Resolver
	cookies            *cookies.Manager
}

func (g *GoAuth) Options() GoAuthOptions            { return g.options }
func (g *GoAuth) Plugins() map[string]plugin.Plugin { return g.plugins }
func (g *GoAuth) Hooks() plugin.HookRegistry        { return g.hooks }

// func (g *GoAuth) ILegacyAuthServices() interfaces1.ILegacyAuthServices { return g.iLegacyAuthServices }
// func (g *GoAuth) MiddleWare() middleware.AuthMiddleware              { return g.middleWare }
func (g *GoAuth) MiddlewareInt() middleware.IAuthMiddleware          { return g.middlewareInt }
func (g *GoAuth) RevocationStore() middleware.RevocationStore        { return g.revocationStore }
func (g *GoAuth) TransactionManager() interfaces.ITransactionManager { return g.transactionManager }
func (g *GoAuth) Provider() *providers.IProviderS                    { return g.provider }
func (g *GoAuth) Repositories() repo_interfaces.IAuthRepos           { return g.repositories }
func (g *GoAuth) Sessions() *sessionsvc.Manager                      { return g.sessions }
func (g *GoAuth) Auth() *authsvc.Service                             { return g.auth }
func (g *GoAuth) SessionResolver() *humaadapter.Resolver             { return g.sessionResolver }
func (g *GoAuth) Cookies() *cookies.Manager                          { return g.cookies }

type GoAuthOptions struct {
	config.AuthConfig
	Conn             *gorm.DB
	Repositories     repo_interfaces.IAuthRepos
	Migrator         migration.IMigrator
	TxManager        interfaces.ITransactionManager
	SecondaryStorage sec_storage.SecondaryStorage
	Plugins          []plugin.Plugin
}

// Plugin returns the registered plugin by ID, or nil if not found.
func (g *GoAuth) Plugin(id string) plugin.Plugin {
	if g.plugins == nil {
		return nil
	}
	return g.plugins[id]
}

// GetPlugin retrieves a plugin by ID with compile-time type assertion.
func GetPlugin[T any](g *GoAuth, id string) (T, bool) {
	if g.plugins == nil {
		var zero T
		return zero, false
	}
	p, ok := g.plugins[id]
	if !ok {
		var zero T
		return zero, false
	}
	typed, ok := p.(T)
	return typed, ok
}

func SetupGoAuth(ctx context.Context, api huma.API, opts GoAuthOptions) (*GoAuth, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if api == nil {
		return nil, errors.New("goauth: huma API instance is required")
	}

	opts.SetDefaults()
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("goauth: invalid options: %w", err)
	}
	if err := authsvc.ValidateConfig(opts.AuthConfig); err != nil {
		return nil, err
	}

	types.InstallScopedErrorHandler()
	if opts.Advanced.GoAuth.OverrideHumaErrors {
		types.InstallGlobalErrorOverride()
	}
	// every route goauth and its plugins register is marked so its errors use the goauth format
	api = types.WrapAPI(api)
	// store the *http.Request in ctx for every goauth and plugin route registered below, so plugin handlers
	// get the client IP / user agent for new sessions and user callbacks receive the request
	api.UseMiddleware(humaadapter.RequestContext())

	models.SetTableNames(opts.GoAuth.TablePrefix, opts.GoAuth.TableNames)
	if opts.Conn != nil {
		opts.Conn.Config.NamingStrategy = gormutil.NewNamingStrategy(opts.GoAuth.TablePrefix, opts.GoAuth.TableNames)
		gormutil.RegisterCallbacks(opts.Conn)
	}

	if opts.Conn == nil && opts.Repositories == nil {
		return nil, errors.New("goauth: either Conn (*gorm.DB) or Repositories (repo_interfaces.IAuthRepos) must be provided")
	}

	// 0. Resolve the ID generator (Advanced.Database.GenerateID, else IDFormat; default better-auth's random
	// 32-char IDs). It is installed process-wide so plugins calling idgen.GenerateID use the same format.
	generateID, err := opts.Advanced.Database.IDGenerator()
	if err != nil {
		return nil, fmt.Errorf("goauth: %w", err)
	}
	idgen.SetGenerator(generateID)
	// config: Advanced.GoAuth.ErrorRequestID shows the request ID of internal errors to clients
	autherr.SetExposeRequestID(opts.Advanced.GoAuth.ErrorRequestID)

	// 1. Resolve Repositories
	repoOpts := []gormauth.RepoOption{gormauth.WithGenerateID(generateID)}
	repos := opts.Repositories
	if repos == nil && opts.Conn != nil {
		repos = gormauth.NewAuthRepos(opts.Conn, repoOpts...)
	}
	// delete expired verifications whenever one is read, like better-auth (opt out with Verification.DisableCleanup)
	if !opts.Verification.DisableCleanup {
		repos = verifycleanup.Wrap(repos)
	}

	// 2. Resolve Migrator
	migrator := opts.Migrator
	if migrator == nil && opts.Conn != nil {
		migrator = core_migration.NewGORMAdminMigrator(opts.Conn)
	}
	if migrator != nil {
		if err := migrator.Migrate(ctx); err != nil {
			return nil, err
		}
	}

	// 3. Resolve Transaction Manager
	txManager := opts.TxManager
	if txManager == nil && opts.Conn != nil {
		txManager = gormutil.NewGormTxManager(opts.Conn)
	}

	//=======================  Middlewares ==============================================|
	//                                                                                   |
	//===================================================================================|
	// 4. Initialize Core Middleware (unaware of access tokens, session/cookie-only)
	memRevocation := middleware.NewKeyValRevocationStore(opts.SecondaryStorage)
	mdlWare := middleware.NewAuthMiddleware(memRevocation, nil)

	//====================       ! End of middleware ! ===============================|
	//                                                                                |
	//================================================================================

	// initialize the provider
	providerService := providers.NewProvider(opts.Conn, opts.SecondaryStorage, mdlWare, txManager)

	// Initialize lifecycle hooks
	hooks := plugin.NewHookRegistry()

	// one session store for cookie, bearer and legacy JWT clients
	cookieMgr := cookies.New(opts.AuthConfig)
	sessOpts := []sessionsvc.ManagerOption{sessionsvc.WithGenerateID(generateID)}
	sessionMgr := sessionsvc.NewManager(opts.Session, repos, repos, opts.SecondaryStorage, hooks, sessOpts...)
	mdlWare.WithSessions(humaadapter.NewSessionClaims(sessionMgr, cookieMgr, repos))

	resolver := humaadapter.NewResolver(sessionMgr, cookieMgr)
	//=============   Register the better-auth compatable routes
	authService := authsvc.New(authsvc.Deps{Config: opts.AuthConfig, Repos: repos, Sessions: sessionMgr, Tx: txManager, Hooks: hooks})
	// Validate the plugin list before anything is initialized: unique IDs and installed dependencies
	if err := validatePlugins(opts.Plugins); err != nil {
		return nil, err
	}
	// Record the user/session fields of the installed plugins: like better-auth, the user and session JSON
	// always carries them (false / null when unset), and update-user knows which keys exist
	var schemaFields []dtos.SchemaFields
	for _, p := range opts.Plugins {
		if sp, ok := p.(plugin.SchemaFieldsProvider); ok && p != nil {
			schemaFields = append(schemaFields, sp.SchemaFields())
		}
	}
	dtos.SetInstalledSchemaFields(schemaFields...)

	// Initialize plugins
	pluginMap := make(map[string]plugin.Plugin)
	authenticate := authenticator.NewDefaultAuthenticator(repos)
	initCtx := &plugin.InitContext{
		Ctx:              ctx,
		Api:              api,
		Config:           opts.AuthConfig,
		TxManager:        txManager,
		SessionManager:   sessionMgr,
		IAuthSvc:         authService,
		IAuthRepos:       repos,
		MiddleWare:       mdlWare,
		Authenticator:    authenticate,
		Hooks:            hooks,
		SecondaryStorage: opts.SecondaryStorage,
		DB:               opts.Conn,
		CookieManager:    cookieMgr,
		GenerateID:       generateID,
	}

	// Phase 1: Initialize plugins (transport/middleware plugins first so global middlewares wrap all plugin routes)
	isTransportPlugin := func(id string) bool {
		return id == "bearer" || id == "access-token" || id == "jwt"
	}
	initPlugin := func(p plugin.Plugin) error {
		if p == nil {
			return nil
		}
		if _, already := pluginMap[p.ID()]; already {
			return nil
		}
		if err := p.Init(initCtx); err != nil {
			return fmt.Errorf("goauth: plugin initialization failed for %s: %w", p.ID(), err)
		}
		if hp, ok := p.(plugin.HookProvider); ok && hp.Hooks() != nil {
			hooks.Register(hp.Hooks())
		}
		pluginMap[p.ID()] = p
		return nil
	}
	// 1a. Init transport/middleware plugins
	for _, p := range opts.Plugins {
		if p != nil && isTransportPlugin(p.ID()) {
			if err := initPlugin(p); err != nil {
				return nil, err
			}
		}
	}

	// Register operation-level security policy middleware after transport plugins (so bearer and
	// access-token resolve credentials first) and before domain plugins / core routes snapshot middlewares.
	origins := origin.New(opts.AuthConfig)
	api.UseMiddleware(humaadapter.SecurityMiddleware(opts.AuthConfig, sessionMgr, cookieMgr, origins))
	// goauth's one after-hook middleware: OnNewSession hooks (e.g. anonymous account linking) and OnResponse
	// hooks (multi-session cookies, one-time-token header, pluginkit.UseAfterHook). It is registered before
	// any domain plugin or core route is mounted, so it wraps every route whatever the plugin order.
	api.UseMiddleware(humaadapter.ResponseHooks(opts.AuthConfig, hooks, cookieMgr))

	// 1b. Init all remaining plugins
	for _, p := range opts.Plugins {
		if p != nil && !isTransportPlugin(p.ID()) {
			if err := initPlugin(p); err != nil {
				return nil, err
			}
		}
	}

	// Phase 2: Run migrations for all plugins (now fully configured with DB)
	for _, p := range opts.Plugins {
		if p == nil {
			continue
		}
		if mig := p.Migrator(); mig != nil {
			if err := mig.Migrate(ctx); err != nil {
				return nil, fmt.Errorf("goauth: plugin migration failed for %s: %w", p.ID(), err)
			}
			slog.Info("migrated plugin", "plugin", p.ID())
		}
	}

	//=============   Register the better-auth compatable routes
	// Register after plugins so plugin middlewares (like bearer) wrap all routes
	humaadapter.RegisterRoutes(api, humaadapter.Deps{
		Conf: opts.AuthConfig, Auth: authService, Sessions: sessionMgr, Cookies: cookieMgr, Resolver: resolver,
		Origins: origins,
	})
	// fail when two plugins (or a plugin and core) registered the same route or operation ID
	if err := types.RegistrationError(api); err != nil {
		return nil, fmt.Errorf("goauth: conflicting routes: %w", err)
	}

	return &GoAuth{
		options: opts,
		plugins: pluginMap,
		hooks:   hooks,
		//middlewares
		// middleWare:         *mdlWare,
		middlewareInt: mdlWare,
		//middleware
		revocationStore:    memRevocation,
		transactionManager: txManager,
		provider:           providerService,
		repositories:       repos,
		sessions:           sessionMgr,
		auth:               authService,
		sessionResolver:    resolver,
		cookies:            cookieMgr,
	}, nil
}

// validatePlugins fails when two plugins share an ID or a plugin's Dependencies() are not installed.
func validatePlugins(list []plugin.Plugin) error {
	// Step 1: collect IDs; the same ID twice means two plugins would register the same routes
	ids := make(map[string]bool, len(list))
	for _, p := range list {
		if p == nil {
			continue
		}
		if ids[p.ID()] {
			return fmt.Errorf("goauth: plugin %q is registered twice", p.ID())
		}
		ids[p.ID()] = true
	}
	// Step 2: every declared dependency must be installed
	var errs []error
	for _, p := range list {
		dp, ok := p.(plugin.DependencyProvider)
		if p == nil || !ok {
			continue
		}
		for _, dep := range dp.Dependencies() {
			if !ids[dep] {
				errs = append(errs, fmt.Errorf("goauth: plugin %q requires plugin %q, which is not installed", p.ID(), dep))
			}
		}
	}
	return errors.Join(errs...)
}

// StartCleanup deletes expired sessions and expired verifications every interval until ctx is cancelled.
// Expired verifications are already purged on read (unless Verification.DisableCleanup); this ticker is for
// long-running servers that also want rows nobody reads again (abandoned codes, expired sessions) removed.
func (g *GoAuth) StartCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				g.cleanupOnce(ctx)
			}
		}
	}()
}

// cleanupOnce runs one cleanup pass: expired sessions, then expired verifications.
func (g *GoAuth) cleanupOnce(ctx context.Context) {
	// Step 1: expired session rows
	if err := g.sessions.CleanupExpired(ctx); err != nil {
		slog.Error("goauth: session cleanup failed", "err", err)
	}
	// Step 2: expired verification rows
	if err := g.repositories.DeleteExpiredVerifications(ctx); err != nil {
		slog.Error("goauth: verification cleanup failed", "err", err)
	}
}

// StartSessionCleanup deletes expired sessions every interval until ctx is cancelled.
func (g *GoAuth) StartSessionCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := g.sessions.CleanupExpired(ctx); err != nil {
					slog.Error("goauth: session cleanup failed", "err", err)
				}
			}
		}
	}()
}
