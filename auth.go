package goauth

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/better-go-auth/goauth/src/app/core"
	"github.com/better-go-auth/goauth/src/app/core/core_interfaces"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins"

	"github.com/better-go-auth/goauth/src/providers"
	"github.com/birukbelay/gocmn/src/server/middleware"
	"github.com/danielgtaylor/huma/v2"
)

type GoAuth struct {
	AuthServices core_interfaces.IAuthServices
	MiddleWare   middleware.AuthMiddleware
}

func SetupGoAuth(api huma.API, opts config.GoAuthOptions) (*GoAuth, error) {

	/*
		- validate the config and throw error if important fields
		- initialize the provider here
	*/

	txManager := gormutil.NewGormTxManager(opts.Conn)
	verifier := middleware.NewJWTTokenVerifier(opts.SessionConfig.AccessSecret)
	mdlWare := middleware.NewAuthMiddleware(verifier, nil, nil)
	//initialize the provider
	providerService := providers.NewProvider(opts.Conn, opts.SecondaryStorage, mdlWare, txManager)

	//setup the auth routes
	authSvc := core.SetupAllAuthRoutes(api, opts.SessionConfig, opts.EmailVerification, providerService)

	// Initialize plugins
	pluginMap := make(map[string]plugin.Plugin)
	initCtx := &plugin.InitContext{
		Ctx: context.Background(),
		Api: api,
		// Config:      cfg,

		TxManager: txManager,
		Extras: map[string]any{
			"jwt_secret": opts.SessionConfig.AccessSecret,
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
		AuthServices: authSvc,
		MiddleWare:   *mdlWare,
	}, nil
}
