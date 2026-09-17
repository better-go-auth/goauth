package core

import (
	"github.com/better-go-auth/goauth/src/app/core/auth"
	"github.com/better-go-auth/goauth/src/app/core/profile"
	"github.com/better-go-auth/goauth/src/app/core/session"
	"github.com/better-go-auth/goauth/src/app/core/verification"
	gormauthrepo "github.com/better-go-auth/goauth/src/app/repository/gormauth"
	"github.com/better-go-auth/goauth/src/app/services/serv_interfaces"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/providers"
	"github.com/danielgtaylor/huma/v2"
)

func SetupAllAuthRoutes(api huma.API, conf config.AuthConfig, vCfg config.EmailVerification, provServ *providers.IProviderS) serv_interfaces.IAuthServices {
	// define the services
	vSvc := verification.NewVerificationService(provServ.GormConn, vCfg)
	sSvc := session.NewService(conf.SessionConfig, provServ)
	accountRepo := gormauthrepo.NewAccountRepo(provServ.GormConn)
	authSvc := auth.NewAuthService(&conf.SessionConfig, provServ, vSvc, sSvc, accountRepo)
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
