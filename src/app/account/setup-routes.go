package account

import (
	"github.com/better-go-auth/goauth/src/app/account/account_interfaces"
	"github.com/better-go-auth/goauth/src/app/account/auth"
	"github.com/better-go-auth/goauth/src/app/account/session"
	"github.com/better-go-auth/goauth/src/app/account/verification"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/providers"
	"github.com/danielgtaylor/huma/v2"
)

func SetupAllAuthRoutes(api huma.API, conf config.SessionConfig, vCfg config.EmailVerification, provServ *providers.IProviderS) account_interfaces.IAuthServices {
	//define the services
	vSvc := verification.NewVerificationService(provServ.GormConn, vCfg)
	sSvc := session.NewService(conf, provServ)
	authSvc := auth.NewAuthService(&conf, provServ, vSvc, sSvc)

	session.SetupSessionRoutes(api, provServ, sSvc)
	auth.SetupAuthRoutes(api, provServ, authSvc)
	return account_interfaces.AuthServiceImpl{
		IVerificationService: vSvc,
		ISessionService:      sSvc,
	}
}
