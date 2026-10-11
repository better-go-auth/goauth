package auth

import (
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	interfaces1 "github.com/better-go-auth/goauth/src/plugins/access-token/services/interfaces"
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
	VSvc   interfaces1.IVerificationService
	SesSvc interfaces1.LegacySessionService
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

func NewAuthService(conf *config.SessionGoAuth, provSvc *providers.IProviderS, vSvc interfaces1.IVerificationService, sSvc interfaces1.LegacySessionService, authRepos repo_interfaces.IAuthRepos, hooks ...plugins.HookRegistry) *LegacyService {
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
