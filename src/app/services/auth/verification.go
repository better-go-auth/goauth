package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
)

// requestType values of better-auth's change-email tokens.
const (
	changeEmailConfirmation = "change-email-confirmation"
	changeEmailVerification = "change-email-verification"
)

// sendVerificationMinDuration is better-auth's constant-time floor for anonymous send-verification-email.
var sendVerificationMinDuration = 500 * time.Millisecond

// emailVerificationToken is better-auth's createEmailVerificationToken: an HS256 JWT signed with the secret.
func (s *Service) emailVerificationToken(email, updateTo, requestType string) (string, error) {
	claims := map[string]any{"email": strings.ToLower(email)}
	if updateTo != "" {
		claims["updateTo"] = strings.ToLower(updateTo)
	}
	if requestType != "" {
		claims["requestType"] = requestType
	}
	return authcrypto.SignJWT(claims, s.cfg.Secret, s.cfg.EmailVerification.ExpiresIn)
}

func (s *Service) verifyURL(token, callbackURL string) string {
	if callbackURL == "" {
		callbackURL = "/"
	}
	return s.baseURL() + "/verify-email?token=" + token + "&callbackURL=" + url.QueryEscape(callbackURL)
}

// baseURL is better-auth's ctx.context.baseURL: BaseURL + BasePath.
func (s *Service) baseURL() string {
	return strings.TrimRight(s.cfg.BaseURL, "/") + s.cfg.BasePath
}

// sendVerificationEmail is better-auth's sendVerificationEmailFn; it is a no-op without a sender.
func (s *Service) sendVerificationEmail(ctx context.Context, user *models.User, callbackURL string) error {
	send := s.cfg.EmailVerification.SendVerificationEmail
	if send == nil {
		return nil
	}
	tok, err := s.emailVerificationToken(user.Email, "", "")
	if err != nil {
		return err
	}
	return send(config.EmailVerificationData{User: *user, URL: s.verifyURL(tok, callbackURL), Token: tok}, request(ctx))
}

// SendVerificationEmail mirrors better-auth's POST /send-verification-email.
func (s *Service) SendVerificationEmail(ctx context.Context, current *dtos.SessionWithUser, in dtos.SendVerificationEmailInput) error {
	if s.cfg.EmailVerification.SendVerificationEmail == nil {
		return autherr.ErrVerificationEmailNotEnabled
	}
	if current == nil {
		start := time.Now()
		var sendErr error
		user, err := lookup(s.repos.FindUserByEmail(ctx, strings.ToLower(in.Email)))
		if err != nil {
			return err
		}
		if user == nil || user.EmailVerified {
			_, _ = s.emailVerificationToken(in.Email, "", "")
		} else {
			sendErr = s.sendVerificationEmail(ctx, user, in.CallbackURL)
		}
		if rest := sendVerificationMinDuration - time.Since(start); rest > 0 {
			select {
			case <-time.After(rest):
			case <-ctx.Done():
			}
		}
		return sendErr
	}
	if !strings.EqualFold(current.User.Email, in.Email) {
		return autherr.ErrEmailMismatch
	}
	if current.User.EmailVerified {
		return autherr.ErrEmailAlreadyVerified
	}
	user, err := s.repos.FindUserByID(ctx, current.User.ID)
	if err != nil {
		return err
	}
	return s.sendVerificationEmail(ctx, user, in.CallbackURL)
}

// VerifyEmail mirrors better-auth's GET /verify-email, including the change-email token types.
// current is the caller's session (nil when signed out).
func (s *Service) VerifyEmail(ctx context.Context, current *dtos.SessionWithUser, token, callbackURL string, meta Meta) (*VerifyEmailResult, error) {
	claims, err := authcrypto.VerifyJWT(token, s.cfg.Secret)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, autherr.ErrTokenExpired.WithStatus(http.StatusUnauthorized)
		}
		return nil, autherr.ErrInvalidToken.WithStatus(http.StatusUnauthorized)
	}
	email, _ := claims["email"].(string)
	updateTo, _ := claims["updateTo"].(string)
	requestType, _ := claims["requestType"].(string)
	if !validEmail(email) {
		return nil, autherr.ErrInvalidToken.WithStatus(http.StatusUnauthorized)
	}
	user, err := lookup(s.repos.FindUserByEmail(ctx, email))
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, autherr.ErrUserNotFound.WithStatus(http.StatusUnauthorized)
	}

	if updateTo != "" {
		if current != nil && current.User.Email != email {
			return nil, autherr.ErrInvalidUser.WithStatus(http.StatusUnauthorized)
		}
		return s.verifyEmailChange(ctx, current, user, updateTo, requestType, callbackURL, meta)
	}

	if user.EmailVerified {
		return &VerifyEmailResult{Status: true}, nil
	}
	ev := s.cfg.EmailVerification
	if ev.BeforeEmailVerification != nil {
		if err := ev.BeforeEmailVerification(*user, request(ctx)); err != nil {
			return nil, err
		}
	}
	updated, err := s.repos.UpdateUser(ctx, user.ID, map[string]interface{}{"EmailVerified": true})
	if err != nil {
		return nil, autherr.ErrFailedToUpdateUser
	}
	s.sessions.RefreshUser(ctx, updated)
	if ev.AfterEmailVerification != nil {
		if err := ev.AfterEmailVerification(*updated, request(ctx)); err != nil {
			return nil, err
		}
	}
	res := &VerifyEmailResult{Status: true}
	if ev.AutoSignInAfterVerification {
		if current == nil || current.User.Email != email {
			sw, err := s.sessions.Create(ctx, updated, meta, sessionsvc.CreateOptions{})
			if err != nil {
				return nil, autherr.ErrFailedToCreateSession
			}
			res.Session = sw
		} else {
			sw := *current
			sw.User = dtos.UserFromModel(updated)
			res.Session = &sw
		}
	}
	return res, nil
}

func (s *Service) verifyEmailChange(ctx context.Context, current *dtos.SessionWithUser, user *models.User, updateTo, requestType, callbackURL string, meta Meta) (*VerifyEmailResult, error) {
	// user clicked the confirmation sent to the old address: now verify the new one
	if requestType == changeEmailConfirmation {
		tok, err := s.emailVerificationToken(user.Email, updateTo, changeEmailVerification)
		if err != nil {
			return nil, err
		}
		if send := s.cfg.EmailVerification.SendVerificationEmail; send != nil {
			target := *user
			target.Email = updateTo
			if err := send(config.EmailVerificationData{User: target, URL: s.verifyURL(tok, callbackURL), Token: tok}, request(ctx)); err != nil {
				return nil, err
			}
		}
		return &VerifyEmailResult{Status: true}, nil
	}

	active := current
	if active == nil {
		sw, err := s.sessions.Create(ctx, user, meta, sessionsvc.CreateOptions{})
		if err != nil {
			return nil, autherr.ErrFailedToCreateSession
		}
		active = sw
	}
	// change-email-verification: the new address is proven; legacy tokens (no requestType) still need verifying
	verified := requestType == changeEmailVerification
	updated, err := s.repos.UpdateUser(ctx, user.ID, map[string]interface{}{"Email": updateTo, "EmailVerified": verified})
	if err != nil {
		return nil, autherr.ErrFailedToUpdateUser
	}
	s.sessions.RefreshUser(ctx, updated)
	if verified {
		if after := s.cfg.EmailVerification.AfterEmailVerification; after != nil {
			if err := after(*updated, request(ctx)); err != nil {
				return nil, err
			}
		}
	} else if err := s.sendVerificationEmail(ctx, updated, callbackURL); err != nil {
		return nil, err
	}
	sw := *active
	sw.User = dtos.UserFromModel(updated)
	out := dtos.UserFromModel(updated)
	return &VerifyEmailResult{Status: true, User: &out, Session: &sw}, nil
}

// ChangeEmail mirrors better-auth's POST /change-email. It returns the session to rewrite
// when the email was changed immediately (unverified users with UpdateEmailWithoutVerification).
func (s *Service) ChangeEmail(ctx context.Context, current *dtos.SessionWithUser, in dtos.ChangeEmailInput) (*dtos.SessionWithUser, error) {
	if current == nil {
		return nil, autherr.ErrUnauthorized
	}
	ce := s.cfg.User.ChangeEmail
	if !ce.Enabled {
		return nil, autherr.ErrChangeEmailDisabled
	}
	newEmail := strings.ToLower(in.NewEmail)
	if !validEmail(newEmail) {
		return nil, autherr.ErrInvalidEmail
	}
	if newEmail == current.User.Email {
		return nil, ErrEmailIsTheSame
	}
	callbackURL := deref(in.CallbackURL)
	sendVerification := s.cfg.EmailVerification.SendVerificationEmail
	withoutVerification := !current.User.EmailVerified && ce.UpdateEmailWithoutVerification
	withConfirmation := sendVerification != nil && current.User.EmailVerified && ce.SendChangeEmailConfirmation != nil
	if !withoutVerification && !withConfirmation && sendVerification == nil {
		return nil, autherr.ErrVerificationEmailNotEnabled
	}

	existing, err := lookup(s.repos.FindUserByEmail(ctx, newEmail))
	if err != nil {
		return nil, err
	}
	if existing != nil {
		// same work as the success path, so the response does not reveal the address is taken
		_, _ = s.emailVerificationToken(current.User.Email, newEmail, "")
		return nil, nil
	}

	if withoutVerification {
		updated, err := s.repos.UpdateUser(ctx, current.User.ID, map[string]interface{}{"Email": newEmail})
		if err != nil {
			return nil, autherr.ErrFailedToUpdateUser
		}
		s.sessions.RefreshUser(ctx, updated)
		if err := s.sendVerificationEmail(ctx, updated, callbackURL); err != nil {
			return nil, err
		}
		sw := *current
		sw.User = dtos.UserFromModel(updated)
		return &sw, nil
	}

	user, err := s.repos.FindUserByID(ctx, current.User.ID)
	if err != nil {
		return nil, err
	}
	if withConfirmation {
		tok, err := s.emailVerificationToken(user.Email, newEmail, changeEmailConfirmation)
		if err != nil {
			return nil, err
		}
		return nil, ce.SendChangeEmailConfirmation(config.ChangeEmailConfirmationData{
			User: *user, NewEmail: newEmail, URL: s.verifyURL(tok, callbackURL), Token: tok,
		}, request(ctx))
	}
	tok, err := s.emailVerificationToken(user.Email, newEmail, changeEmailVerification)
	if err != nil {
		return nil, err
	}
	target := *user
	target.Email = newEmail
	return nil, sendVerification(config.EmailVerificationData{User: target, URL: s.verifyURL(tok, callbackURL), Token: tok}, request(ctx))
}
