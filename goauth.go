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
	authsvc "github.com/better-go-auth/goauth/src/app/services/auth"
	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/migration"
	core_migration "github.com/better-go-auth/goauth/src/models/migration/core-migration"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	interfaces1 "github.com/better-go-auth/goauth/src/plugins/access-token/services/interfaces"
	"github.com/better-go-auth/goauth/src/providers/authenticator"
	"github.com/better-go-auth/goauth/src/providers/cookies"
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
	options             GoAuthOptions
	plugins             map[string]plugin.Plugin
	hooks               plugin.HookRegistry
	iLegacyAuthServices interfaces1.ILegacyAuthServices
	middleWare          middleware.AuthMiddleware
	middlewareInt       middleware.IAuthMiddleware
	revocationStore     middleware.RevocationStore
	transactionManager  interfaces.ITransactionManager
	provider            *providers.IProviderS
	repositories        repo_interfaces.IAuthRepos
	sessions            *sessionsvc.Manager
	auth                *authsvc.Service
	sessionResolver     *humaadapter.Resolver
	cookies             *cookies.Manager
}

func (g *GoAuth) Options() GoAuthOptions                            { return g.options }
func (g *GoAuth) Plugins() map[string]plugin.Plugin                 { return g.plugins }
func (g *GoAuth) Hooks() plugin.HookRegistry                        { return g.hooks }
func (g *GoAuth) ILegacyAuthServices() interfaces1.ILegacyAuthServices { return g.iLegacyAuthServices }
func (g *GoAuth) MiddleWare() middleware.AuthMiddleware              { return g.middleWare }
func (g *GoAuth) MiddlewareInt() middleware.IAuthMiddleware          { return g.middlewareInt }
func (g *GoAuth) RevocationStore() middleware.RevocationStore        { return g.revocationStore }
func (g *GoAuth) TransactionManager() interfaces.ITransactionManager { return g.transactionManager }
func (g *GoAuth) Provider() *providers.IProviderS                   { return g.provider }
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

	models.SetTableNames(opts.GoAuth.TablePrefix, opts.GoAuth.TableNames)
	if opts.Conn != nil && (opts.GoAuth.TablePrefix != "" || len(opts.GoAuth.TableNames) > 0) {
		opts.Conn.Config.NamingStrategy = models.NewNamingStrategy(opts.GoAuth.TablePrefix, opts.GoAuth.TableNames)
	}

	if opts.Conn == nil && opts.Repositories == nil {
		return nil, errors.New("goauth: either Conn (*gorm.DB) or Repositories (repo_interfaces.IAuthRepos) must be provided")
	}

	// 1. Resolve Repositories
	var repoOpts []gormauth.RepoOption
	if opts.Advanced.Database.GenerateID != nil {
		repoOpts = append(repoOpts, gormauth.WithGenerateID(opts.Advanced.Database.GenerateID))
	}
	repos := opts.Repositories
	if repos == nil && opts.Conn != nil {
		repos = gormauth.NewAuthRepos(opts.Conn, repoOpts...)
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
	verifier := middleware.NewJWTTokenVerifier(opts.GoAuth.Session.JWT.AccessSecret)
	var revocationStore middleware.RevocationStore
	if repos != nil {
		revocationStore = providers.NewRevocationStoreWithRepo(repos, opts.SecondaryStorage, opts.AuthConfig.GoAuth.Session.JWT)
	} 
	// else {
	// 	revocationStore = providers.NewRevocationStore(opts.Conn, opts.SecondaryStorage, opts.AuthConfig.GoAuth.Session.JWT)
	// }

	// make a middleware
	mdlWare := middleware.NewAuthMiddleware(verifier, revocationStore, nil)
	// initialize the provider
	providerService := providers.NewProvider(opts.Conn, opts.SecondaryStorage, mdlWare, txManager)

	// Initialize lifecycle hooks
	hooks := plugin.NewHookRegistry()

	// one session store for cookie, bearer and legacy JWT clients
	cookieMgr := cookies.New(opts.AuthConfig)
	var sessOpts []sessionsvc.ManagerOption
	if opts.Advanced.Database.GenerateID != nil {
		sessOpts = append(sessOpts, sessionsvc.WithGenerateID(opts.Advanced.Database.GenerateID))
	}
	sessionMgr := sessionsvc.NewManager(opts.Session, repos, repos, opts.SecondaryStorage, hooks, sessOpts...)
	mdlWare.WithSessions(humaadapter.NewSessionClaims(sessionMgr, cookieMgr, repos))

	resolver := humaadapter.NewResolver(sessionMgr, cookieMgr)
	//=============   Register the better-auth compatable routes
	authService := authsvc.New(authsvc.Deps{Config: opts.AuthConfig, Repos: repos, Sessions: sessionMgr, Tx: txManager, Hooks: hooks})
	// Initialize plugins
	pluginMap := make(map[string]plugin.Plugin)
	authenticate := authenticator.NewDefaultAuthenticator(opts.GoAuth.Session.JWT.AccessSecret, repos)
	initCtx := &plugin.InitContext{
		Ctx:            ctx,
		Api:            api,
		Config:         opts.AuthConfig,
		TxManager:      txManager,
		SessionManager: sessionMgr,
		IAuthSvc:       authService,

		IAuthRepos:       repos,
		MiddleWare:       mdlWare,
		Authenticator:    authenticate,
		Hooks:            hooks,
		SecondaryStorage: opts.SecondaryStorage,
		DB:               opts.Conn,
		CookieManager:    cookieMgr,
		GenerateID:       opts.Advanced.Database.GenerateID,
	}

	// Phase 1: Initialize plugins (repos, services, and migrators configured via initCtx)
	for _, p := range opts.Plugins {
		if p == nil {
			continue
		}
		if err := p.Init(initCtx); err != nil {
			return nil, fmt.Errorf("goauth: plugin initialization failed for %s: %w", p.ID(), err)
		}
		if hp, ok := p.(plugin.HookProvider); ok && hp.Hooks() != nil {
			hooks.Register(hp.Hooks())
		}
		pluginMap[p.ID()] = p
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
		Origins: origin.New(opts.AuthConfig),
	})

	return &GoAuth{
		options:            opts,
		plugins:            pluginMap,
		hooks:              hooks,
		middleWare:         *mdlWare,
		revocationStore:    revocationStore,
		transactionManager: txManager,
		provider:           providerService,
		repositories:       repos,
		middlewareInt:      mdlWare,
		sessions:           sessionMgr,
		auth:               authService,
		sessionResolver:    resolver,
		cookies:            cookieMgr,
	}, nil
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
