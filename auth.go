package goauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/better-go-auth/goauth/src/app/core"
	"github.com/better-go-auth/goauth/src/app/core/core_interfaces"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	"github.com/better-go-auth/goauth/src/config"
	core_migration "github.com/better-go-auth/goauth/src/models/migration/core-migration"
	plugin "github.com/better-go-auth/goauth/src/plugins"

	"github.com/better-go-auth/goauth/src/providers"
	"github.com/birukbelay/gocmn/src/server/middleware"
	"github.com/danielgtaylor/huma/v2"
)

type GoAuth struct {
	IAuthServices core_interfaces.IAuthServices
	// AuthServices
	MiddleWare        middleware.AuthMiddleware
	RevocationStore   middleware.RevocationStore
	TransctionManager interfaces.ITransactionManager
	Provider          *providers.IProviderS
}

func SetupGoAuth(api huma.API, opts config.GoAuthOptions) (*GoAuth, error) {
	if api == nil {
		return nil, errors.New("goauth: huma API instance is required")
	}

	opts.SetDefaults()
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("goauth: invalid options: %w", err)
	}
	migrator := core_migration.NewGORMAdminMigrator(opts.Conn)
	if err := migrator.Migrate(context.Background()); err != nil {
		return nil, err
	}

	txManager := gormutil.NewGormTxManager(opts.Conn)
	verifier := middleware.NewJWTTokenVerifier(opts.SessionConfig.AccessSecret)
	revocationStore := providers.NewRevocationStore(opts.Conn, opts.SecondaryStorage)
	mdlWare := middleware.NewAuthMiddleware(verifier, revocationStore, nil)
	//initialize the provider
	providerService := providers.NewProvider(opts.Conn, opts.SecondaryStorage, mdlWare, txManager)

	//setup the auth routes
	authSvc := core.SetupAllAuthRoutes(api, opts, opts.EmailVerification, providerService)

	// Initialize plugins
	pluginMap := make(map[string]plugin.Plugin)
	initCtx := &plugin.InitContext{
		Ctx:           context.Background(),
		Api:           api,
		TxManager:     txManager,
		IAuthServices: authSvc,
		Extras:        map[string]any{
			// "jwt_secret":      opts.SessionConfig.AccessSecret,
			// "session_service": authSvc,
		},
	}

	for _, p := range opts.Plugins {
		if p == nil {
			continue
		}
		if err := p.Init(initCtx); err != nil {
			return nil, fmt.Errorf("goauth: plugin initialization failed for %s: %w", p.ID(), err)
		}
		if mig := p.Migrator(); mig != nil {
			if err := mig.Migrate(context.Background()); err != nil {
				return nil, fmt.Errorf("goauth: plugin migration failed for %s: %w", p.ID(), err)
			}
			slog.Info("migrated plugin", "plugin", p.ID())
		}
		pluginMap[p.ID()] = p
	}

	return &GoAuth{
		IAuthServices:     authSvc,
		MiddleWare:        *mdlWare,
		RevocationStore:   revocationStore,
		TransctionManager: txManager,
		Provider:          providerService,
	}, nil
}
