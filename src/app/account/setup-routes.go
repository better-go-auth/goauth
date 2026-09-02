package account

import (
	"github.com/better-go-auth/goauth/src/app/account/auth"
	"github.com/better-go-auth/goauth/src/app/account/session"
	"github.com/better-go-auth/goauth/src/app/account/verification"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/providers"
	"github.com/danielgtaylor/huma/v2"
)

func SetupAllAuthRoutes(api huma.API, conf *config.EnvConfig, provServ *providers.IProviderS) {
	//define the services
	vSvc := verification.NewVerificationService(provServ.GormConn, provServ.VerificationCodeSender)
	sSvc := session.NewService(provServ)
	authSvc := auth.NewAuthService(conf, provServ, vSvc, sSvc)

	session.SetupSessionRoutes(api, provServ, sSvc)
	auth.SetupAuthRoutes(api, provServ, authSvc)
}
