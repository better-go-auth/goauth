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
func resetPasswordIdentifier(token string) string { return "reset-password:" + token }

// RequestPasswordReset mirrors better-auth's POST /request-password-reset (formerly /forget-password).
// Unknown emails succeed silently.
func (s *Service) RequestPasswordReset(ctx context.Context, in dtos.RequestPasswordResetInput) error {
	send := s.cfg.EmailAndPassword.SendResetPassword
	if send == nil {
		return ErrResetPasswordDisabled
	}
	user, err := lookup(s.repos.FindUserByEmail(ctx, strings.ToLower(in.Email)))
	if err != nil {
		return err
	}
	if user == nil {
		// same lookups as the success path to blunt timing attacks
		_ = idgen.GenerateToken()
		_, _ = s.repos.FindVerificationValue(ctx, "dummy-verification-token")
		return nil
	}
	tok := idgen.GenerateToken()
	_, err = s.repos.UpsertVerificationValue(ctx, &models.Verification{
		Base:       models.Base{ID: models.NewID()},
		Identifier: resetPasswordIdentifier(tok),
		Value:      user.ID,
		ExpiresAt:  time.Now().Add(s.cfg.EmailAndPassword.ResetPasswordTokenExpiresIn).UTC(),
	})
	if err != nil {
		return autherr.ErrFailedToCreateVerification
	}
	link := s.baseURL() + "/reset-password/" + tok + "?callbackURL=" + url.QueryEscape(in.RedirectTo)
	return send(config.ResetPasswordData{User: *user, URL: link, Token: tok}, request(ctx))
}

// findResetToken returns the live reset verification for token.
func (s *Service) findResetToken(ctx context.Context, token string) (*models.Verification, error) {
	if token == "" {
		return nil, autherr.ErrInvalidToken
	}
	v, err := lookup(s.repos.FindVerificationValue(ctx, resetPasswordIdentifier(token)))
	if err != nil {
		return nil, err
	}
	if v == nil || v.IsExpired() {
		return nil, autherr.ErrInvalidToken
	}
	return v, nil
}

// ValidateResetToken backs better-auth's GET /reset-password/:token (the adapter redirects with ?token= or ?error=INVALID_TOKEN).
func (s *Service) ValidateResetToken(ctx context.Context, token string) error {
	_, err := s.findResetToken(ctx, token)
	return err
}

// ResetPassword mirrors better-auth's POST /reset-password.
func (s *Service) ResetPassword(ctx context.Context, in dtos.ResetPasswordInput) error {
	if in.Token == "" {
		return autherr.ErrInvalidToken
	}
	if err := s.checkPasswordLength(in.NewPassword); err != nil {
		return err
	}
	v, err := s.findResetToken(ctx, in.Token)
	if err != nil {
		return err
	}
	// consume first so the token is single-use
	if err := s.repos.DeleteVerificationByIdentifier(ctx, v.Identifier); err != nil {
		return err
	}
	userID := v.Value
	hash, err := s.passwords.Hash(in.NewPassword)
	if err != nil {
		return err
	}
	err = s.inTx(ctx, func(ctx context.Context) error {
		account, err := lookup(s.repos.FindAccountByUserAndProvider(ctx, userID, models.ProvCredential))
		if err != nil {
			return err
		}
		if account == nil {
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
	if cb := s.cfg.EmailAndPassword.OnPasswordReset; cb != nil {
		if user, _ := lookup(s.repos.FindUserByID(ctx, userID)); user != nil {
			if err := cb(config.PasswordResetData{User: *user}, request(ctx)); err != nil {
				return err
			}
		}
	}
	if s.cfg.EmailAndPassword.RevokeSessionsOnPasswordReset {
		return s.sessions.DeleteUserSessions(ctx, userID)
	}
	return nil
}

// ChangePassword mirrors better-auth's POST /change-password. With RevokeOtherSessions every
// session is revoked and a replacement is returned in the result.
func (s *Service) ChangePassword(ctx context.Context, current *dtos.SessionWithUser, in dtos.ChangePasswordInput, meta Meta) (*ChangePasswordResult, error) {
	if current == nil {
		return nil, autherr.ErrUnauthorized
	}
	if err := s.checkPasswordLength(in.NewPassword); err != nil {
		return nil, err
	}
	account, err := s.credentialAccount(ctx, current.User.ID)
	if err != nil {
		return nil, err
	}
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
	if !in.RevokeOtherSessions {
		return res, nil
	}
	if err := s.sessions.DeleteUserSessions(ctx, current.User.ID); err != nil {
		return nil, err
	}
	user, err := s.repos.FindUserByID(ctx, current.User.ID)
	if err != nil {
		return nil, autherr.ErrFailedToGetSession
	}
	sw, err := s.sessions.Create(ctx, user, meta, sessionsvc.CreateOptions{})
	if err != nil {
		return nil, autherr.ErrFailedToGetSession
	}
	res.Token, res.Session = &sw.Session.Token, sw
	return res, nil
}
