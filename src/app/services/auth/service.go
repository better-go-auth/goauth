// Package auth implements better-auth's core email/password, verification, session and
// user self-service flows, ported from better-go-auth's core/services.
//
// It is framework-agnostic and independent from the legacy src/app/core/auth service:
// methods take plain inputs (dtos.*Input, the current session) and return plain results.
// HTTP concerns (cookies, redirects, status codes) belong to the adapters in src/app/adapters.
package auth

import (
	"context"
	"net/http"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
)

// Errors better-auth throws inline (not part of BASE_ERROR_CODES).
var (
	ErrEmailPasswordDisabled       = autherr.Err(http.StatusBadRequest, "EMAIL_PASSWORD_DISABLED", "Email and password is not enabled")
	ErrEmailPasswordSignUpDisabled = autherr.Err(http.StatusBadRequest, "EMAIL_PASSWORD_SIGN_UP_DISABLED", "Email and password sign up is not enabled")
	ErrResetPasswordDisabled       = autherr.Err(http.StatusBadRequest, "RESET_PASSWORD_DISABLED", "Reset password isn't enabled")
	ErrBannedUser                  = autherr.Err(http.StatusForbidden, "BANNED_USER", "You have been banned from this application")
	ErrNoFieldsToUpdate            = autherr.Err(http.StatusBadRequest, "NO_FIELDS_TO_UPDATE", "No fields to update")
	ErrEmailIsTheSame              = autherr.Err(http.StatusBadRequest, "EMAIL_IS_THE_SAME", "Email is the same")
	ErrDeleteUserDisabled          = autherr.Err(http.StatusNotFound, "NOT_FOUND", "Not Found")
)

// Deps are the collaborators of Service. Tx is optional.
type Deps struct {
	Config    config.AuthConfig
	Repos     repo_interfaces.IAuthRepos
	Sessions  *sessionsvc.Manager
	Passwords *authcrypto.Passwords
	Tx        interfaces.ITransactionManager
}

// Service implements IAuthService, ISessionService and IUserService.
type Service struct {
	cfg       config.AuthConfig
	repos     repo_interfaces.IAuthRepos
	sessions  *sessionsvc.Manager
	passwords *authcrypto.Passwords
	tx        interfaces.ITransactionManager
}

var (
	_ IAuthService    = (*Service)(nil)
	_ ISessionService = (*Service)(nil)
	_ IUserService    = (*Service)(nil)
)

// New builds a Service; Passwords defaults to authcrypto.NewPasswords(cfg).
func New(d Deps) *Service {
	if d.Passwords == nil {
		d.Passwords = authcrypto.NewPasswords(d.Config)
	}
	return &Service{cfg: d.Config, repos: d.Repos, sessions: d.Sessions, passwords: d.Passwords, tx: d.Tx}
}

func (s *Service) inTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if s.tx == nil {
		return fn(ctx)
	}
	return s.tx.Transaction(ctx, fn)
}

// emailPasswordEnabled treats an unset Enabled as true (goauth is email/password first).
func (s *Service) emailPasswordEnabled() bool {
	e := s.cfg.EmailAndPassword.Enabled
	return e == nil || *e
}

func (s *Service) checkPasswordLength(pw string) error {
	if len(pw) < s.cfg.EmailAndPassword.MinPasswordLength {
		return autherr.ErrPasswordTooShort
	}
	if len(pw) > s.cfg.EmailAndPassword.MaxPasswordLength {
		return autherr.ErrPasswordTooLong
	}
	return nil
}

func request(ctx context.Context) *http.Request {
	return config.GetHTTPRequest(ctx)
}

func isNotFound(err error) bool {
	ae := autherr.AsAuthError(err)
	return ae != nil && ae.StatusCode == http.StatusNotFound
}

// lookup turns a repository "not found" into (nil, nil).
func lookup[T any](v *T, err error) (*T, error) {
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return v, nil
}
