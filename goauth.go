package goauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/better-go-auth/goauth/src/app/core"
	"github.com/better-go-auth/goauth/src/app/core/ba"
	"github.com/better-go-auth/goauth/src/app/repository/gormauth"
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/app/services/serv_interfaces"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/migration"
	core_migration "github.com/better-go-auth/goauth/src/models/migration/core-migration"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/providers/authenticator"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
	"github.com/better-go-auth/goauth/src/sessions"
	"gorm.io/gorm"

	"github.com/better-go-auth/goauth/src/common/middleware"
	"github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/providers"
	"github.com/danielgtaylor/huma/v2"
)

type GoAuth struct {
	Options            GoAuthOptions
	Plugins            map[string]plugin.Plugin
	Hooks              plugin.HookRegistry
	IAuthServices      serv_interfaces.IAuthServices
	MiddleWare         middleware.AuthMiddleware
	MiddlewareInt      middleware.IAuthMiddleware
	RevocationStore    middleware.RevocationStore
	TransactionManager interfaces.ITransactionManager

	Provider     *providers.IProviderS
	Repositories repo_interfaces.IAuthRepos

	// Sessions manages better-auth style cookie sessions.
	Sessions *sessions.Manager
	// SessionResolver provides Huma middlewares that load the cookie session.
	SessionResolver *sessions.Resolver
	Cookies         *cookies.Manager
}
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
	if g.Plugins == nil {
		return nil
	}
	return g.Plugins[id]
}

// GetPlugin retrieves a plugin by ID with compile-time type assertion.
func GetPlugin[T any](g *GoAuth, id string) (T, bool) {
	if g.Plugins == nil {
		var zero T
		return zero, false
	}
	p, ok := g.Plugins[id]
	if !ok {
		var zero T
		return zero, false
	}
	typed, ok := p.(T)
	return typed, ok
}

func SetupGoAuth(api huma.API, opts GoAuthOptions) (*GoAuth, error) {
	if api == nil {
		return nil, errors.New("goauth: huma API instance is required")
	}

	opts.SetDefaults()
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("goauth: invalid options: %w", err)
	}

	types.InstallScopedErrorHandler()
	if opts.Advanced.GoAuth.OverrideHumaErrors {
		types.InstallGlobalErrorOverride()
	}
	// every route goauth and its plugins register is marked so its errors use the goauth format
	api = types.WrapAPI(api)

	if opts.Advanced.GenerateID != nil {
		models.SetIDGenerator(opts.Advanced.GenerateID)
	}
	models.SetTableNames(opts.GoAuth.TablePrefix, opts.GoAuth.TableNames)

	if opts.Conn == nil && opts.Repositories == nil {
		return nil, errors.New("goauth: either Conn (*gorm.DB) or Repositories (repo_interfaces.IAuthRepos) must be provided")
	}

	// 1. Resolve Repositories
	repos := opts.Repositories
	if repos == nil && opts.Conn != nil {
		repos = gormauth.NewAuthRepos(opts.Conn)
	}

	// 2. Resolve Migrator
	migrator := opts.Migrator
	if migrator == nil && opts.Conn != nil {
		migrator = core_migration.NewGORMAdminMigrator(opts.Conn)
	}
	if migrator != nil {
		if err := migrator.Migrate(context.Background()); err != nil {
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
	} else {
		revocationStore = providers.NewRevocationStore(opts.Conn, opts.SecondaryStorage, opts.AuthConfig.GoAuth.Session.JWT)
	}

	// make a middleware
	mdlWare := middleware.NewAuthMiddleware(verifier, revocationStore, nil)
	// initialize the provider
	providerService := providers.NewProvider(opts.Conn, opts.SecondaryStorage, mdlWare, txManager)

	// Initialize lifecycle hooks
	hooks := plugin.NewHookRegistry()

	// setup the auth routes
	authSvc := core.SetupAllAuthRoutesWithRepos(api, opts.AuthConfig, opts.EmailVerification, providerService, repos, hooks)

	cookieMgr := cookies.New(opts.AuthConfig)
	sessionMgr := sessions.NewManager(opts.Session, repos, repos, opts.SecondaryStorage, hooks)
	resolver := sessions.NewResolver(sessionMgr, cookieMgr)
	if opts.GoAuth.Mode == config.ModeCompat {
		ba.RegisterRoutes(api, ba.Deps{Conf: opts.AuthConfig, Sessions: sessionMgr, Cookies: cookieMgr, Resolver: resolver})
	}

	// Initialize plugins
	pluginMap := make(map[string]plugin.Plugin)
	// TODO: use the session function here
	authenticate := authenticator.NewDefaultAuthenticator(opts.GoAuth.Session.JWT.AccessSecret, repos)
	initCtx := &plugin.InitContext{
		Ctx:           context.Background(),
		Api:           api,
		Config:        opts.AuthConfig,
		TxManager:     txManager,
		IAuthServices: authSvc,
		IAuthRepos:    repos,
		MiddleWare:    mdlWare,
		Authenticator: authenticate,
		Hooks:         hooks,
		Extras:        map[string]any{},
	}

	// Phase 1: Run migrations for all plugins first
	for _, p := range opts.Plugins {
		if p == nil {
			continue
		}
		if mig := p.Migrator(); mig != nil {
			if err := mig.Migrate(context.Background()); err != nil {
				return nil, fmt.Errorf("goauth: plugin migration failed for %s: %w", p.ID(), err)
			}
			slog.Info("migrated plugin", "plugin", p.ID())
		}
	}

	// Phase 2: Initialize plugins and mount routes
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

	return &GoAuth{
		Options:            opts,
		Plugins:            pluginMap,
		Hooks:              hooks,
		IAuthServices:      authSvc,
		MiddleWare:         *mdlWare,
		RevocationStore:    revocationStore,
		TransactionManager: txManager,
		Provider:           providerService,
		Repositories:       repos,
		MiddlewareInt:      mdlWare,
		Sessions:           sessionMgr,
		SessionResolver:    resolver,
		Cookies:            cookieMgr,
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
				if err := g.Sessions.CleanupExpired(ctx); err != nil {
					slog.Error("goauth: session cleanup failed", "err", err)
				}
			}
		}
	}()
}
