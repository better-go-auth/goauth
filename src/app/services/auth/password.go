package auth

import (
	"context"
	"net/url"
	"strings"
	"time"

	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/providers/idgen"
)

// resetPasswordIdentifier is better-auth's verification identifier for reset tokens.
// The verification row is `identifier = "reset-password:<token>"`, `value = userId`, so a TS better-auth
// server sharing the database can redeem links created here and the other way round.
func resetPasswordIdentifier(token string) string { return resetPasswordPrefix + token }

const resetPasswordPrefix = "reset-password:"

// revokeOtherResetLinks applies EmailAndPassword.GoAuth.SingleResetLink: drop every reset token of userID.
func (s *Service) revokeOtherResetLinks(ctx context.Context, userID string) error {
	if !s.cfg.EmailAndPassword.GoAuth.SingleResetLink {
		return nil
	}
	return s.repos.DeleteVerificationsByValue(ctx, resetPasswordPrefix, userID)
}

// RequestPasswordReset mirrors better-auth's POST /request-password-reset (formerly /forget-password).
// Unknown emails succeed silently.
//
// Flow: find the user → store a random one-time token → email a link
// <base>/reset-password/<token>?callbackURL=<redirectTo> through the app's sender.
func (s *Service) RequestPasswordReset(ctx context.Context, in dtos.RequestPasswordResetInput) error {
	// config: EmailAndPassword.SendResetPassword is the app's mailer; without it the endpoint is disabled
	send := s.cfg.EmailAndPassword.SendResetPassword
	if send == nil {
		return ErrResetPasswordDisabled
	}
	user, err := acceptNotFound(s.repos.FindUserByEmail(ctx, strings.ToLower(in.Email)))
	if err != nil {
		return err
	}
	if user == nil {
		// same lookups as the success path to blunt timing attacks
		_ = idgen.GenerateToken()
		_, _ = s.repos.FindVerificationValue(ctx, "dummy-verification-token")
		return nil
	}
	// config: EmailAndPassword.GoAuth.SingleResetLink → links sent earlier stop working
	if err := s.revokeOtherResetLinks(ctx, user.ID); err != nil {
		return err
	}
	// random 32-char token; only someone with access to the inbox gets it
	tok := idgen.GenerateToken()
	_, err = s.repos.UpsertVerificationValue(ctx, &models.Verification{
		Base:       models.Base{ID: models.NewID()},
		Identifier: resetPasswordIdentifier(tok),
		Value:      user.ID,
		// config: EmailAndPassword.ResetPasswordTokenExpiresIn (default 1h)
		ExpiresAt: time.Now().Add(s.cfg.EmailAndPassword.ResetPasswordTokenExpiresIn).UTC(),
	})
	if err != nil {
		return autherr.ErrFailedToCreateVerification
	}
	// GET /reset-password/<token> (ValidateResetToken) redirects to callbackURL with ?token= or ?error=
	link := s.baseURL() + "/reset-password/" + tok + "?callbackURL=" + url.QueryEscape(in.RedirectTo)
	return send(config.ResetPasswordData{User: *user, URL: link, Token: tok}, request(ctx))
}

// findResetToken returns the live reset verification for token.
// Missing, unknown and expired tokens all become INVALID_TOKEN.
func (s *Service) findResetToken(ctx context.Context, token string) (*models.Verification, error) {
	if token == "" {
		return nil, autherr.ErrInvalidToken
	}
	v, err := acceptNotFound(s.repos.FindVerificationValue(ctx, resetPasswordIdentifier(token)))
	if err != nil {
		return nil, err
	}
	if v == nil || v.IsExpired() {
		return nil, autherr.ErrInvalidToken
	}
	return v, nil
}

// ValidateResetToken backs better-auth's GET /reset-password/:token (the adapter redirects with ?token= or ?error=INVALID_TOKEN).
// It only checks the token; it does not use it up.
func (s *Service) ValidateResetToken(ctx context.Context, token string) error {
	_, err := s.findResetToken(ctx, token)
	return err
}

// ResetPassword mirrors better-auth's POST `/reset-password`.
//
// Flow: validate the new password and the token → delete the token (single use) → store the new hash on the
// user's credential account (creating one if the user only had OAuth) → run OnPasswordReset →
// optionally sign the user out everywhere.
func (s *Service) ResetPassword(ctx context.Context, in dtos.ResetPasswordInput) error {
	if in.Token == "" {
		return autherr.ErrInvalidToken
	}
	// config: MinPasswordLength / MaxPasswordLength
	if err := s.checkPasswordLength(in.NewPassword); err != nil {
		return err
	}
	// consume atomically before changing anything: of two concurrent requests with the same token only one gets the row
	v, err := s.repos.ConsumeVerificationValue(ctx, resetPasswordIdentifier(in.Token))
	if err != nil {
		if isNotFound(err) {
			return autherr.ErrInvalidToken
		}
		return err
	}
	// the verification row's value is the user id it was issued for
	userID := v.Value
	hash, err := s.passwords.Hash(in.NewPassword)
	if err != nil {
		return err
	}
	// find-then-create/update the credential account as one unit
	err = s.inTx(ctx, func(ctx context.Context) error {
		account, err := acceptNotFound(s.repos.FindAccountByUserAndProvider(ctx, userID, models.ProvCredential))
		if err != nil {
			return err
		}
		if account == nil {
			// the user had no password yet (e.g. OAuth-only): resetting gives them one
			_, err = s.repos.CreateAccount(ctx, &models.Account{
				Base:       models.Base{ID: models.NewID()},
				UserID:     userID,
				ProviderID: models.ProvCredential,
				AccountID:  userID,
				Password:   &hash,
			})
			return err
		}
		_, err = s.repos.UpdateAccount(ctx, account.ID, map[string]interface{}{"Password": hash})
		return err
	})
	if err != nil {
		return err
	}
	// config: EmailAndPassword.GoAuth.SingleResetLink → other links still in the inbox stop working
	if err := s.revokeOtherResetLinks(ctx, userID); err != nil {
		return err
	}
	// config: EmailAndPassword.OnPasswordReset is called after the password changed (e.g. "your password was reset" email)
	if cb := s.cfg.EmailAndPassword.OnPasswordReset; cb != nil {
		if user, _ := acceptNotFound(s.repos.FindUserByID(ctx, userID)); user != nil {
			if err := cb(config.PasswordResetData{User: *user}, request(ctx)); err != nil {
				return err
			}
		}
	}
	// config: EmailAndPassword.RevokeSessionsOnPasswordReset signs the user out on every device
	if s.cfg.EmailAndPassword.RevokeSessionsOnPasswordReset {
		return s.sessions.DeleteUserSessions(ctx, userID)
	}
	return nil
}

// ChangePassword mirrors better-auth's POST /change-password. With RevokeOtherSessions every
// session is revoked and a replacement is returned in the result.
//
// Flow: validate the new password → load the credential account → check the current password →
// store the new hash → optionally sign out everywhere and start a fresh session for this device.
func (s *Service) ChangePassword(ctx context.Context, current *dtos.SessionWithUser, in dtos.ChangePasswordInput, meta Meta) (*ChangePasswordResult, error) {
	if current == nil {
		return nil, autherr.ErrUnauthorized
	}
	// config: MinPasswordLength / MaxPasswordLength
	if err := s.checkPasswordLength(in.NewPassword); err != nil {
		return nil, err
	}
	// users without a password (OAuth-only) can't change it; they use reset/set-password instead
	account, err := s.credentialAccount(ctx, current.User.ID)
	if err != nil {
		return nil, err
	}
	// hashed before the check, in better-auth's order, so a wrong current password costs the same time
	hash, err := s.passwords.Hash(in.NewPassword)
	if err != nil {
		return nil, err
	}
	if ok, _, err := s.passwords.Verify(*account.Password, in.CurrentPassword); err != nil || !ok {
		return nil, autherr.ErrInvalidPassword
	}
	if _, err := s.repos.UpdateAccount(ctx, account.ID, map[string]interface{}{"Password": hash}); err != nil {
		return nil, err
	}
	res := &ChangePasswordResult{User: current.User}
	// request flag revokeOtherSessions: without it, existing sessions stay valid and token is null
	if !in.RevokeOtherSessions {
		return res, nil
	}
	// revoke all sessions, including the current one...
	if err := s.sessions.DeleteUserSessions(ctx, current.User.ID); err != nil {
		return nil, err
	}
	user, err := s.repos.FindUserByID(ctx, current.User.ID)
	if err != nil {
		return nil, autherr.ErrFailedToGetSession
	}
	// ...then give this device a new one; the adapter sets it as the session cookie
	sw, err := s.sessions.Create(ctx, user, meta, sessionsvc.CreateOptions{})
	if err != nil {
		return nil, autherr.ErrFailedToGetSession
	}
	res.Token, res.Session = &sw.Session.Token, sw
	return res, nil
}
