package core

import (
	"github.com/better-go-auth/goauth/src/app/core/auth"
	"github.com/better-go-auth/goauth/src/app/core/profile"
	"github.com/better-go-auth/goauth/src/app/core/session"
	"github.com/better-go-auth/goauth/src/app/core/verification"
	gormauthrepo "github.com/better-go-auth/goauth/src/app/repository/gormauth"
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/app/services/serv_interfaces"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/providers"
	"github.com/birukbelay/gocmn/src/provider/db"
	"github.com/danielgtaylor/huma/v2"
)

func SetupAllAuthRoutes(api huma.API, conf config.AuthConfig, vCfg config.EmailVerification, provServ *providers.IProviderS, hooks ...plugins.HookRegistry) serv_interfaces.IAuthServices {
	var repos repo_interfaces.IAuthRepos
	if provServ != nil && provServ.GormConn != nil {
		repos = gormauthrepo.NewAuthRepos(provServ.GormConn)
	}
	return SetupAllAuthRoutesWithRepos(api, conf, vCfg, provServ, repos, hooks...)
}

func SetupAllAuthRoutesWithRepos(api huma.API, conf config.AuthConfig, vCfg config.EmailVerification, provServ *providers.IProviderS, repos repo_interfaces.IAuthRepos, hooks ...plugins.HookRegistry) serv_interfaces.IAuthServices {
	var h plugins.HookRegistry
	if len(hooks) > 0 {
		h = hooks[0]
	}

	var vSvc serv_interfaces.IVerificationService
	var sSvc *session.Service
	var accountRepo repo_interfaces.IOAuthAccountRepo

	if repos != nil {
		vSvc = verification.NewVerificationServiceWithRepo(repos, vCfg)
		var secondaryStorage db.KeyValServ
		if provServ != nil {
			secondaryStorage = provServ.SecondaryStorage
		}
		sSvc = session.NewServiceWithRepo(conf.SessionConfig, repos, secondaryStorage, h)
		accountRepo = repos
	} else if provServ != nil && provServ.GormConn != nil {
		vSvc = verification.NewVerificationService(provServ.GormConn, vCfg)
		sSvc = session.NewService(conf.SessionConfig, provServ, h)
		accountRepo = gormauthrepo.NewAccountRepo(provServ.GormConn)
	}

	authSvc := auth.NewAuthService(&conf.SessionConfig, provServ, vSvc, sSvc, accountRepo, h)
	profileServ := profile.NewProfileServH(provServ, vSvc, sSvc, accountRepo)

	// Set up the routes
	session.SetupSessionRoutes(api, provServ, sSvc, conf)
	auth.SetupAuthRoutes(api, provServ, authSvc, conf)
	profile.SetUserProfileRoutes(api, provServ, profileServ, conf)
	return serv_interfaces.AuthServiceImpl{
		IVerificationService: vSvc,
		ISessionService:      sSvc,
	}
}

