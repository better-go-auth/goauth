package auth

import (
	"context"

	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	"github.com/better-go-auth/goauth/src/models/dtos"
)

// Meta is the request metadata stored on sessions created by the service.
type Meta = sessionsvc.Meta

// IAuthService covers sign-up/in/out, email verification and password flows.
type IAuthService interface {
	SignUpEmail(ctx context.Context, in dtos.SignUpEmailInput, meta Meta) (*SignUpResult, error)
	SignInEmail(ctx context.Context, in dtos.SignInEmailInput, meta Meta) (*SignInResult, error)
	SignOut(ctx context.Context, token string) error
	VerifyPassword(ctx context.Context, current *dtos.SessionWithUser, password string) error

	SendVerificationEmail(ctx context.Context, current *dtos.SessionWithUser, in dtos.SendVerificationEmailInput) error
	VerifyEmail(ctx context.Context, current *dtos.SessionWithUser, token, callbackURL string, meta Meta) (*VerifyEmailResult, error)
	ChangeEmail(ctx context.Context, current *dtos.SessionWithUser, in dtos.ChangeEmailInput) (*dtos.SessionWithUser, error)

	RequestPasswordReset(ctx context.Context, in dtos.RequestPasswordResetInput) error
	ValidateResetToken(ctx context.Context, token string) error
	ResetPassword(ctx context.Context, in dtos.ResetPasswordInput) error
	ChangePassword(ctx context.Context, current *dtos.SessionWithUser, in dtos.ChangePasswordInput, meta Meta) (*ChangePasswordResult, error)
}

// ISessionService covers the session self-service endpoints.
type ISessionService interface {
	GetSession(ctx context.Context, token string, opt GetSessionOptions) (*GetSessionResult, error)
	ListSessions(ctx context.Context, current *dtos.SessionWithUser) ([]dtos.BetterAuthSession, error)
	RevokeSession(ctx context.Context, current *dtos.SessionWithUser, token string) error
	RevokeSessions(ctx context.Context, current *dtos.SessionWithUser) error
	RevokeOtherSessions(ctx context.Context, current *dtos.SessionWithUser) error
}

// IUserService covers the user self-service endpoints (admin actions live in the admin plugin).
type IUserService interface {
	UpdateUser(ctx context.Context, current *dtos.SessionWithUser, in UpdateUserInput) (*dtos.SessionWithUser, error)
	DeleteUser(ctx context.Context, current *dtos.SessionWithUser, password *string) error
	ListAccounts(ctx context.Context, current *dtos.SessionWithUser) ([]dtos.AccountResponse, error)
	UnlinkAccount(ctx context.Context, current *dtos.SessionWithUser, in dtos.UnlinkAccountInput) error
}

// SignUpResult is better-auth's { token, user }; Session is set when the user was signed in.
type SignUpResult struct {
	Token        *string
	User         dtos.BetterAuthUser
	Session      *dtos.SessionWithUser
	DontRemember bool
}

// SignInResult is better-auth's { redirect, token, url, user } plus the new session.
type SignInResult struct {
	Redirect     bool
	Token        string
	URL          *string
	User         dtos.BetterAuthUser
	Session      *dtos.SessionWithUser
	DontRemember bool
}

// VerifyEmailResult is better-auth's { status, user }. Session is set when the session cookie must be (re)written.
type VerifyEmailResult struct {
	Status  bool
	User    *dtos.BetterAuthUser
	Session *dtos.SessionWithUser
}

// ChangePasswordResult is better-auth's { token, user }; Session is the replacement session when others were revoked.
type ChangePasswordResult struct {
	Token   *string
	User    dtos.BetterAuthUser
	Session *dtos.SessionWithUser
}

// GetSessionOptions mirrors get-session's query and cookies.
type GetSessionOptions struct {
	DisableRefresh bool
	// DeferRefresh reports NeedsRefresh instead of writing (session.deferSessionRefresh on GET).
	DeferRefresh bool
	// DontRemember is set when the dont_remember cookie is present.
	DontRemember bool
}

// GetSessionResult is nil-Session when there is no live session.
type GetSessionResult struct {
	Session      *dtos.SessionWithUser
	NeedsRefresh bool
	// Refreshed is set when the expiry was extended and the cookie must be rewritten.
	Refreshed bool
}

// UpdateUserInput is better-auth's update-user body: name, image and goauth's extra profile fields.
type UpdateUserInput struct {
	Name  *string
	Image *string
	// Email is rejected (EMAIL_CAN_NOT_BE_UPDATED); use ChangeEmail.
	Email *string
	// Fields holds additional user fields keyed by Go field name (e.g. "DisplayName").
	Fields map[string]any
}
