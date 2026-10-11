package auth

import (
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/app/services/serv_interfaces"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/providers"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
)

type GinAuthHandler struct {
	AuthServ *LegacyService
	CmnServ  *providers.IProviderS
	Cookies  CookieAttrs
}
type LegacyService struct {
	Config   *config.SessionGoAuth
	Provider *providers.IProviderS
	// services
	VSvc   serv_interfaces.IVerificationService
	SesSvc serv_interfaces.LegacySessionService
	// repos
	userRepo    repo_interfaces.IUserRepo
	accountRepo repo_interfaces.IOAuthAccountRepo
	sessionRepo repo_interfaces.ISessionRepo
	// hooks & txn
	TxMgr interfaces.ITransactionManager
	Hooks plugins.HookRegistry
	// Passwords hashes/verifies passwords; nil means legacy bcrypt.
	Passwords *authcrypto.Passwords
}

func NewAuthService(conf *config.SessionGoAuth, provSvc *providers.IProviderS, vSvc serv_interfaces.IVerificationService, sSvc serv_interfaces.LegacySessionService, authRepos repo_interfaces.IAuthRepos, hooks ...plugins.HookRegistry) *LegacyService {
	var h plugins.HookRegistry
	if len(hooks) > 0 {
		h = hooks[0]
	}
	var txMgr interfaces.ITransactionManager
	if provSvc != nil {
		txMgr = provSvc.TxManager
	}

	return &LegacyService{
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

func NewAuthHandler(cmnServ *providers.IProviderS, serv *LegacyService) *GinAuthHandler {
	// you can migrate auth models here
	return &GinAuthHandler{
		AuthServ: serv,
		CmnServ:  cmnServ,
	}
}
