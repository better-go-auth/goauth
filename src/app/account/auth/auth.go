package auth

import (
	"github.com/better-go-auth/goauth/src/app/account/account_interfaces"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/providers"
)

type GinAuthHandler struct {
	AdminAuthServ *Service
	CmnServ       *providers.IProviderS
}
type Service struct {
	Config   *config.EnvConfig
	Provider *providers.IProviderS
	VSvc     account_interfaces.IVerificationService
}

func NewAuthService(conf *config.EnvConfig, genServ *providers.IProviderS, vSvc account_interfaces.IVerificationService) *Service {
	return &Service{
		Config:   conf,
		Provider: genServ,
		VSvc:     vSvc,
	}
}

func NewAuthHandler(cmnServ *providers.IProviderS, serv *Service) *GinAuthHandler {
	//you can migrate auth models here
	return &GinAuthHandler{
		AdminAuthServ: serv,
		CmnServ:       cmnServ,
	}
}
