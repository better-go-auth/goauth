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
	ErrNoFieldsToUpdate            = autherr.Err(http.StatusBadRequest, "NO_FIELDS_TO_UPDATE", "No fields to update")
	ErrEmailIsTheSame              = autherr.Err(http.StatusBadRequest, "EMAIL_IS_THE_SAME", "Email is the same")
	ErrDeleteUserDisabled          = autherr.Err(http.StatusNotFound, "NOT_FOUND", "Not Found")
)

// Deps are the collaborators of Service. Tx is optional.
type Deps struct {
	Config    config.AuthConfig              // all behaviour switches (sign-up rules, hooks, senders, lifetimes)
	Repos     repo_interfaces.IAuthRepos     // user, account, session and verification storage (GORM or memory)
	Sessions  *sessionsvc.Manager            // creates/reads/revokes sessions in the DB and/or secondary storage
	Passwords *authcrypto.Passwords          // hashes and verifies passwords; built from Config when nil
	Tx        interfaces.ITransactionManager // groups multi-row writes; nil runs them without a transaction
}

// Service implements IAuthService, ISessionService and IUserService.
type Service struct {
	cfg       config.AuthConfig
	repos     repo_interfaces.IAuthRepos
	sessions  *sessionsvc.Manager
	passwords *authcrypto.Passwords
	tx        interfaces.ITransactionManager
	// sessionFields maps client-writable session JSON names to Go field names (GoAuth.Session.UpdatableFields)
	sessionFields map[string]string
}

var (
	// compile-time checks that Service implements all three interfaces
	_ IAuthService    = (*Service)(nil)
	_ ISessionService = (*Service)(nil)
	_ IUserService    = (*Service)(nil)
)

// New builds a Service from its dependencies.
// When no password hasher is injected it builds the default one from the config:
// scrypt (better-auth format) in compat mode, bcrypt in legacy mode, or EmailAndPassword.Password when set.
func New(d Deps) *Service {
	if d.Passwords == nil {
		d.Passwords = authcrypto.NewPasswords(d.Config)
	}
	// invalid names are reported by ValidateConfig at setup; here they just disable update-session
	fields, _ := updatableSessionFields(d.Config)
	return &Service{cfg: d.Config, repos: d.Repos, sessions: d.Sessions, passwords: d.Passwords, tx: d.Tx, sessionFields: fields}
}

// inTx runs fn inside a database transaction when a transaction manager was injected.
// Without one (e.g. the in-memory repositories in tests) fn runs directly.
func (s *Service) inTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if s.tx == nil {
		return fn(ctx)
	}
	// the manager puts the tx in ctx; repositories pick it up from there
	return s.tx.Transaction(ctx, fn)
}

// emailPasswordEnabled reads EmailAndPassword.Enabled. better-auth defaults it to false,
// but goauth treats an unset (nil) value as true because email/password is its main sign-in method.
func (s *Service) emailPasswordEnabled() bool {
	e := s.cfg.EmailAndPassword.Enabled
	return e == nil || *e
}

// checkPasswordLength enforces EmailAndPassword.MinPasswordLength / MaxPasswordLength
// (defaults 8 and 128, set in config.SetDefaults).
func (s *Service) checkPasswordLength(pw string) error {
	if len(pw) < s.cfg.EmailAndPassword.MinPasswordLength {
		return autherr.ErrPasswordTooShort
	}
	if len(pw) > s.cfg.EmailAndPassword.MaxPasswordLength {
		return autherr.ErrPasswordTooLong
	}
	return nil
}

// request returns the *http.Request the adapter stored in ctx (nil outside HTTP).
// It is passed to user callbacks, which receive the request like better-auth's hooks do.
func request(ctx context.Context) *http.Request {
	return config.GetHTTPRequest(ctx)
}

// isNotFound reports whether err is a repository "not found" (both repository implementations return a 404 AuthError).
func isNotFound(err error) bool {
	ae := autherr.AsAuthError(err)
	return ae != nil && ae.StatusCode == http.StatusNotFound
}

// acceptNotFound turns a repository "not found" into (nil, nil), so callers can write
// `if user == nil` instead of checking the error kind. Any other error is returned unchanged.
func acceptNotFound[T any](v *T, err error) (*T, error) {
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return v, nil
}
