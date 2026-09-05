package auth

import (
	"github.com/better-go-auth/goauth/src/app/core/core_interfaces"
	"github.com/better-go-auth/goauth/src/app/repoimpl"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/providers"
)

type GinAuthHandler struct {
	AdminAuthServ *Service
	CmnServ       *providers.IProviderS
}
type Service struct {
	Config      *config.SessionConfig
	Provider    *providers.IProviderS
	VSvc        core_interfaces.IVerificationService
	SesSvc      core_interfaces.ISessionService
	TxMgr       interfaces.ITransactionManager
	accountRepo repoimpl.IOAuthAccountRepo
}

func NewAuthService(conf *config.SessionConfig, provSvc *providers.IProviderS, vSvc core_interfaces.IVerificationService, sSvc core_interfaces.ISessionService, accountRepo repoimpl.IOAuthAccountRepo) *Service {
	return &Service{
		Config:      conf,
		Provider:    provSvc,
		VSvc:        vSvc,
		SesSvc:      sSvc,
		TxMgr:       provSvc.TxManager,
		accountRepo: accountRepo,
	}
}

func NewAuthHandler(cmnServ *providers.IProviderS, serv *Service) *GinAuthHandler {
	//you can migrate auth models here
	return &GinAuthHandler{
		AdminAuthServ: serv,
		CmnServ:       cmnServ,
	}
}
