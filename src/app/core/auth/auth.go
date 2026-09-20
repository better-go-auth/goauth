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
	Config   *config.SessionConfig
	Provider *providers.IProviderS
	// services
	VSvc   serv_interfaces.IVerificationService
	SesSvc serv_interfaces.ISessionService
	// repos
	userRepo    repo_interfaces.IUserRepo
	accountRepo repo_interfaces.IOAuthAccountRepo
	sessionRepo repo_interfaces.ISessionRepo
	// hooks & txn
	TxMgr interfaces.ITransactionManager
	Hooks plugins.HookRegistry
}

func NewAuthService(conf *config.SessionConfig, provSvc *providers.IProviderS, vSvc serv_interfaces.IVerificationService, sSvc serv_interfaces.ISessionService, authRepos repo_interfaces.IAuthRepos, hooks ...plugins.HookRegistry) *Service {
	var h plugins.HookRegistry
	if len(hooks) > 0 {
		h = hooks[0]
	}
	var txMgr interfaces.ITransactionManager
	if provSvc != nil {
		txMgr = provSvc.TxManager
	}

	return &Service{
		Config:      conf,
		Provider:    provSvc,
		VSvc:        vSvc,
		SesSvc:      sSvc,
		TxMgr:       txMgr,
		userRepo:    authRepos,
		accountRepo: authRepos,
		sessionRepo: authRepos,
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
