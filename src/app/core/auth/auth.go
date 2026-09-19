package auth

import (
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/app/services/serv_interfaces"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/providers"
)

type GinAuthHandler struct {
	AdminAuthServ *Service
	CmnServ       *providers.IProviderS
}
type Service struct {
	Config      *config.SessionConfig
	Provider    *providers.IProviderS
	VSvc        serv_interfaces.IVerificationService
	SesSvc      serv_interfaces.ISessionService
	TxMgr       interfaces.ITransactionManager
	accountRepo repo_interfaces.IOAuthAccountRepo
	Hooks       plugins.HookRegistry
}

func NewAuthService(conf *config.SessionConfig, provSvc *providers.IProviderS, vSvc serv_interfaces.IVerificationService, sSvc serv_interfaces.ISessionService, accountRepo repo_interfaces.IOAuthAccountRepo, hooks ...plugins.HookRegistry) *Service {
	var h plugins.HookRegistry
	if len(hooks) > 0 {
		h = hooks[0]
	}
	return &Service{
		Config:      conf,
		Provider:    provSvc,
		VSvc:        vSvc,
		SesSvc:      sSvc,
		TxMgr:       provSvc.TxManager,
		accountRepo: accountRepo,
		Hooks:       h,
	}
}

func NewAuthHandler(cmnServ *providers.IProviderS, serv *Service) *GinAuthHandler {
	// you can migrate auth models here
	return &GinAuthHandler{
		AdminAuthServ: serv,
		CmnServ:       cmnServ,
	}
}
