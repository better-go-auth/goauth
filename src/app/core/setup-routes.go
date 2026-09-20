package core

import (
	"github.com/better-go-auth/goauth/src/app/core/auth"
	"github.com/better-go-auth/goauth/src/app/core/profile"
	"github.com/better-go-auth/goauth/src/app/core/session"
	"github.com/better-go-auth/goauth/src/app/core/verification"
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/app/services/serv_interfaces"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/providers"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
	"github.com/danielgtaylor/huma/v2"
)

func SetupAllAuthRoutesWithRepos(api huma.API, conf config.AuthConfig, vCfg config.EmailVerification, provServ *providers.IProviderS, repos repo_interfaces.IAuthRepos, hooks ...plugins.HookRegistry) serv_interfaces.IAuthServices {
	var h plugins.HookRegistry
	if len(hooks) > 0 {
		h = hooks[0]
	}

	if repos == nil {
		panic("no repos provided")
	}

	vSvc := verification.NewVerificationServiceWithRepo(repos, vCfg)
	var secondaryStorage sec_storage.SecondaryStorage
	if provServ != nil {
		secondaryStorage = provServ.SecondaryStorage
	}
	sSvc := session.NewServiceWithRepo(conf.SessionConfig, repos, secondaryStorage, h)

	// else if provServ != nil && provServ.GormConn != nil {
	// 	vSvc = verification.NewVerificationService(provServ.GormConn, vCfg)
	// 	sSvc = session.NewService(conf.SessionConfig, provServ, h)

	// }

	authSvc := auth.NewAuthService(&conf.SessionConfig, provServ, vSvc, sSvc, repos, h)
	profileServ := profile.NewProfileServH(provServ, vSvc, sSvc, repos)

	// Set up the routes
	session.SetupSessionRoutes(api, provServ, sSvc, conf)
	auth.SetupAuthRoutes(api, provServ, authSvc, conf)
	profile.SetUserProfileRoutes(api, provServ, profileServ, conf)
	return serv_interfaces.AuthServiceImpl{
		IVerificationService: vSvc,
		ISessionService:      sSvc,
	}
}
