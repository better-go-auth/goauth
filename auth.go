package goauth

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/better-go-auth/goauth/src/app/account"
	"github.com/better-go-auth/goauth/src/app/account/account_interfaces"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugin"
	"github.com/better-go-auth/goauth/src/providers"
	"github.com/birukbelay/gocmn/src/provider/db"
	"github.com/birukbelay/gocmn/src/server/middleware"
	"github.com/danielgtaylor/huma/v2"
	"gorm.io/gorm"
)

type GoAuth struct {
	AuthServices account_interfaces.IAuthServices
	MiddleWare   middleware.AuthMiddleware
}

type GoAuthOptions struct {
	Conn              *gorm.DB
	EmailVerification config.EmailVerification
	SessionConfig     config.SessionConfig
	SecondaryStorage  db.KeyValServ
	Plugins           []plugin.Plugin
}

func SetupGoAuth(api huma.API, opts GoAuthOptions) (*GoAuth, error) {

	/*
		- validate the config and throw error if important fields
		- initialize the provider here
	*/

	verifier := middleware.NewJWTTokenVerifier(opts.SessionConfig.AccessSecret)
	mdlWare := middleware.NewAuthMiddleware(verifier, nil, nil)
	//initialize the provider
	providerService := providers.NewProvider(opts.Conn, opts.SecondaryStorage, mdlWare)

	txManager := gormutil.NewGormTxManager(opts.Conn)
	//setup the auth routes
	authSvc := account.SetupAllAuthRoutes(api, opts.SessionConfig, opts.EmailVerification, providerService)

	// Initialize plugins
	pluginMap := make(map[string]plugin.Plugin)
	initCtx := &plugin.InitContext{
		Ctx: context.Background(),
		Api: api,
		// Config:      cfg,

		TxManager: txManager,
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
