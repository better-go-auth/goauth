package services

import (
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	authint "github.com/better-go-auth/goauth/src/app/services/interfaces"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins"
	accTokInterfaces "github.com/better-go-auth/goauth/src/plugins/access-token/services/interfaces"
	"github.com/better-go-auth/goauth/src/providers"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
)

// AuthService implements IAccessTokenAuthService for legacy JWT/token authentication.
type AuthService struct {
	Config   *config.SessionGoAuth
	Provider *providers.IProviderS
	// services
	VSvc        accTokInterfaces.IVerificationService
	SesSvc      *SessionService
	coreAuthSvc authint.IAuthService
	// repos
	UserRepo    repo_interfaces.IUserRepo
	AccountRepo repo_interfaces.IOAuthAccountRepo
	SessionRepo repo_interfaces.ISessionRepo
	// hooks & txn
	TxMgr interfaces.ITransactionManager
	Hooks plugins.HookRegistry
	// Passwords hashes/verifies passwords; nil means legacy bcrypt.
	Passwords *authcrypto.Passwords
}

var _ accTokInterfaces.IAccessTokenAuthService = (*AuthService)(nil)

// NewAuthService creates a new AuthService for the access-token plugin.
func NewAuthService(
	conf *config.SessionGoAuth,
	coreAuthSvc authint.IAuthService,
	vSvc accTokInterfaces.IVerificationService,
	sSvc *SessionService,
	authRepos repo_interfaces.IAuthRepos,
	txMgr interfaces.ITransactionManager,
	passwords *authcrypto.Passwords,
	hooks ...plugins.HookRegistry,
) *AuthService {
	var h plugins.HookRegistry
	if len(hooks) > 0 {
		h = hooks[0]
	}
	return &AuthService{
		Config:      conf,
		VSvc:        vSvc,
		SesSvc:      sSvc,
		UserRepo:    authRepos,
		AccountRepo: authRepos,
		SessionRepo: authRepos,
		TxMgr:       txMgr,
		Passwords:   passwords,
		Hooks:       h,
		coreAuthSvc: coreAuthSvc,
	}
}
