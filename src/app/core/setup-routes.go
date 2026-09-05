package core

import (
	gormauthrepo "github.com/better-go-auth/goauth/src/app/core/account/repo"
	"github.com/better-go-auth/goauth/src/app/core/auth"
	"github.com/better-go-auth/goauth/src/app/core/core_interfaces"
	"github.com/better-go-auth/goauth/src/app/core/profile"
	"github.com/better-go-auth/goauth/src/app/core/session"
	"github.com/better-go-auth/goauth/src/app/core/verification"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/providers"
	"github.com/danielgtaylor/huma/v2"
)

func SetupAllAuthRoutes(api huma.API, conf config.SessionConfig, vCfg config.EmailVerification, provServ *providers.IProviderS) core_interfaces.IAuthServices {
	//define the services
	vSvc := verification.NewVerificationService(provServ.GormConn, vCfg)
	sSvc := session.NewService(conf, provServ)
	accountRepo := gormauthrepo.NewAccountRepo(provServ.GormConn)
	authSvc := auth.NewAuthService(&conf, provServ, vSvc, sSvc, accountRepo)
	profileServ := profile.NewProfileServH[models.User](provServ, vSvc, sSvc, accountRepo)

	//Set up the routes
	session.SetupSessionRoutes(api, provServ, sSvc)
	auth.SetupAuthRoutes(api, provServ, authSvc)
	profile.SetUserProfileRoutes(api, provServ, profileServ)
	return core_interfaces.AuthServiceImpl{
		IVerificationService: vSvc,
		ISessionService:      sSvc,
	}
}
