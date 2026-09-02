package auth

import (
	"github.com/better-go-auth/goauth/src/app/account/account_interfaces"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/providers"
)

type GinAuthHandler struct {
	AdminAuthServ *Service
	CmnServ       *providers.IProviderS
}
type Service struct {
	Config   *config.SessionConfig
	Provider *providers.IProviderS
	VSvc     account_interfaces.IVerificationService
	SesSvc   account_interfaces.ISessionService
	TxMgr    interfaces.ITransactionManager
}

func NewAuthService(conf *config.SessionConfig, provSvc *providers.IProviderS, vSvc account_interfaces.IVerificationService, sSvc account_interfaces.ISessionService) *Service {
	return &Service{
		Config:   conf,
		Provider: provSvc,
		VSvc:     vSvc,
		SesSvc:   sSvc,
		TxMgr:    gormutil.NewGormTxManager(provSvc.GormConn),
	}
}

func NewAuthHandler(cmnServ *providers.IProviderS, serv *Service) *GinAuthHandler {
	//you can migrate auth models here
	return &GinAuthHandler{
		AdminAuthServ: serv,
		CmnServ:       cmnServ,
	}
}
