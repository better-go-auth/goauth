package auth

import (
	"context"

	"github.com/better-go-auth/goauth/src/models"
)

// VerificationSender is implemented by *Service for plugin sign-in endpoints (e.g. /sign-in/username) that
// re-send the verification email to unverified users like /sign-in/email does. Plugins get the service as
// InitContext.IAuthSvc and type-assert it to this interface.
type VerificationSender interface {
	// HasVerificationSender reports whether verification emails can be sent (app sender or plugin override).
	HasVerificationSender() bool
	// SendVerificationEmailTo emails user a verification link (or the plugin override's message).
	SendVerificationEmailTo(ctx context.Context, user *models.User, callbackURL string) error
}

var _ VerificationSender = (*Service)(nil)

// HasVerificationSender reports whether verification emails can be sent.
func (s *Service) HasVerificationSender() bool { return s.hasVerificationSender() }

// SendVerificationEmailTo is better-auth's sendVerificationEmailFn for plugin endpoints.
func (s *Service) SendVerificationEmailTo(ctx context.Context, user *models.User, callbackURL string) error {
	if user == nil {
		return nil
	}
	return s.sendVerificationEmail(ctx, user, callbackURL)
}
