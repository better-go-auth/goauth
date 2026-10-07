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
// Nothing is stored in the database; the signature and expiry are the proof.
//   - email: the address being verified (or the current address in a change-email flow)
//   - updateTo: set only for change-email, the new address
//   - requestType: set only for change-email, which step of that flow the link is for
func (s *Service) emailVerificationToken(email, updateTo, requestType string) (string, error) {
	claims := map[string]any{"email": strings.ToLower(email)}
	if updateTo != "" {
		claims["updateTo"] = strings.ToLower(updateTo)
	}
	if requestType != "" {
		claims["requestType"] = requestType
	}
	// config: Secret signs the token (shared with a TS better-auth server, so its links work here too);
	// EmailVerification.ExpiresIn sets how long the link is valid (default 1h)
	return authcrypto.SignJWT(claims, s.cfg.Secret, s.cfg.EmailVerification.ExpiresIn)
}

// verifyURL builds the link put in emails: <base>/verify-email?token=...&callbackURL=...
// The callback URL is where the browser is redirected after verification ("/" by default).
func (s *Service) verifyURL(token, callbackURL string) string {
	if callbackURL == "" {
		callbackURL = "/"
	}
	return s.baseURL() + "/verify-email?token=" + token + "&callbackURL=" + url.QueryEscape(callbackURL)
}

// baseURL is better-auth's ctx.context.baseURL: BaseURL + BasePath.
// config: BaseURL (e.g. https://app.com) and BasePath (default /api/auth).
func (s *Service) baseURL() string {
	return strings.TrimRight(s.cfg.BaseURL, "/") + s.cfg.BasePath
}

// sendVerificationEmail is better-auth's sendVerificationEmailFn: build a token + link and pass them
// to the app's sender. It is a no-op without a sender.
func (s *Service) sendVerificationEmail(ctx context.Context, user *models.User, callbackURL string) error {
	// config: EmailVerification.SendVerificationEmail is the app's function that actually sends the email
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
//
// Signed out: anyone can ask for a link for any email, so the response must not reveal whether the email
// exists or is already verified. Unknown/verified emails do the same token work and every call takes at least
// 500ms, so timing is equal too.
// Signed in: the email must be the session user's own, still unverified, address.
func (s *Service) SendVerificationEmail(ctx context.Context, current *dtos.SessionWithUser, in dtos.SendVerificationEmailInput) error {
	// config: without an EmailVerification.SendVerificationEmail sender the endpoint is disabled
	if s.cfg.EmailVerification.SendVerificationEmail == nil {
		return autherr.ErrVerificationEmailNotEnabled
	}
	if current == nil {
		start := time.Now()
		var sendErr error
		user, err := acceptNotFound(s.repos.FindUserByEmail(ctx, strings.ToLower(in.Email)))
		if err != nil {
			return err
		}
		if user == nil || user.EmailVerified {
			// nothing to send; sign a token anyway so this branch costs about the same
			_, _ = s.emailVerificationToken(in.Email, "", "")
		} else {
			sendErr = s.sendVerificationEmail(ctx, user, in.CallbackURL)
		}
		// pad the response to the minimum duration (stop early if the request is cancelled)
		if rest := sendVerificationMinDuration - time.Since(start); rest > 0 {
			select {
			case <-time.After(rest):
			case <-ctx.Done():
			}
		}
		return sendErr
	}
	// signed in: only for your own address
	if !strings.EqualFold(current.User.Email, in.Email) {
		return autherr.ErrEmailMismatch
	}
	if current.User.EmailVerified {
		return autherr.ErrEmailAlreadyVerified
	}
	// load the full user model (the session only holds the public user fields) for the sender callback
	user, err := s.repos.FindUserByID(ctx, current.User.ID)
	if err != nil {
		return err
	}
	return s.sendVerificationEmail(ctx, user, in.CallbackURL)
}

// VerifyEmail mirrors better-auth's GET /verify-email, including the change-email token types.
// current is the caller's session (nil when signed out).
//
// Flow: check the token's signature and expiry → load the user named in it →
// a change-email token goes to verifyEmailChange; otherwise mark the email verified
// (running the before/after hooks) and optionally sign the user in.
// Errors use 401 like better-auth; the adapter turns them into ?error=CODE redirects when a callbackURL is set.
func (s *Service) VerifyEmail(ctx context.Context, current *dtos.SessionWithUser, token, callbackURL string, meta Meta) (*VerifyEmailResult, error) {
	// config: Secret must be the one that signed the link
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
	user, err := acceptNotFound(s.repos.FindUserByEmail(ctx, email))
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, autherr.ErrUserNotFound.WithStatus(http.StatusUnauthorized)
	}

	// updateTo present = this link belongs to a change-email request
	if updateTo != "" {
		// someone signed in as a different user can't apply another user's email change
		if current != nil && current.User.Email != email {
			return nil, autherr.ErrInvalidUser.WithStatus(http.StatusUnauthorized)
		}
		return s.verifyEmailChange(ctx, current, user, updateTo, requestType, callbackURL, meta)
	}

	// already verified (link clicked twice): succeed without doing anything
	if user.EmailVerified {
		return &VerifyEmailResult{Status: true}, nil
	}
	ev := s.cfg.EmailVerification
	// config: BeforeEmailVerification can veto the verification by returning an error
	if ev.BeforeEmailVerification != nil {
		if err := ev.BeforeEmailVerification(*user, request(ctx)); err != nil {
			return nil, err
		}
	}
	updated, err := s.repos.UpdateUser(ctx, user.ID, map[string]interface{}{"EmailVerified": true})
	if err != nil {
		return nil, autherr.ErrFailedToUpdateUser
	}
	// sessions cached in secondary storage hold a copy of the user; update it so emailVerified is true there too
	s.sessions.RefreshUser(ctx, updated)
	// config: AfterEmailVerification runs once the user is verified (e.g. welcome email)
	if ev.AfterEmailVerification != nil {
		if err := ev.AfterEmailVerification(*updated, request(ctx)); err != nil {
			return nil, err
		}
	}
	res := &VerifyEmailResult{Status: true}
	// config: AutoSignInAfterVerification signs the user in from the link
	if ev.AutoSignInAfterVerification {
		if current == nil || current.User.Email != email {
			// not signed in (or signed in as someone else): start a new session for the verified user
			sw, err := s.sessions.Create(ctx, updated, meta, sessionsvc.CreateOptions{})
			if err != nil {
				return nil, autherr.ErrFailedToCreateSession
			}
			res.Session = sw
		} else {
			// already signed in as this user: keep the session, refresh its user copy
			sw := *current
			sw.User = dtos.UserFromModel(updated)
			res.Session = &sw
		}
	}
	return res, nil
}

// verifyEmailChange handles the change-email links (better-auth's three flows, picked by requestType):
//   - "change-email-confirmation": clicked from the OLD address; now send a verification link to the NEW address.
//   - "change-email-verification": clicked from the NEW address; switch the email and mark it verified.
//   - "" (legacy): switch the email immediately, mark it unverified, and send a normal verification link to it.
//
// The last two need a session for the cookie: the current one, or a new one when signed out.
func (s *Service) verifyEmailChange(ctx context.Context, current *dtos.SessionWithUser, user *models.User, updateTo, requestType, callbackURL string, meta Meta) (*VerifyEmailResult, error) {
	// user clicked the confirmation sent to the old address: now verify the new one
	if requestType == changeEmailConfirmation {
		tok, err := s.emailVerificationToken(user.Email, updateTo, changeEmailVerification)
		if err != nil {
			return nil, err
		}
		// config: the regular verification sender delivers it, addressed to the new email
		if send := s.cfg.EmailVerification.SendVerificationEmail; send != nil {
			target := *user
			target.Email = updateTo
			if err := send(config.EmailVerificationData{User: target, URL: s.verifyURL(tok, callbackURL), Token: tok}, request(ctx)); err != nil {
				return nil, err
			}
		}
		return &VerifyEmailResult{Status: true}, nil
	}

	// the email is about to change: make sure there is a session to write the new user into
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
	// update the user copy inside cached sessions (new email everywhere)
	s.sessions.RefreshUser(ctx, updated)
	if verified {
		// config: AfterEmailVerification also runs when a new address is verified
		if after := s.cfg.EmailVerification.AfterEmailVerification; after != nil {
			if err := after(*updated, request(ctx)); err != nil {
				return nil, err
			}
		}
	} else if err := s.sendVerificationEmail(ctx, updated, callbackURL); err != nil {
		// legacy flow: the new address still has to be verified with a normal link
		return nil, err
	}
	// return the session with the new user so the adapter rewrites the session cookie
	sw := *active
	sw.User = dtos.UserFromModel(updated)
	out := dtos.UserFromModel(updated)
	return &VerifyEmailResult{Status: true, User: &out, Session: &sw}, nil
}

// ChangeEmail mirrors better-auth's POST /change-email. It returns the session to rewrite
// when the email was changed immediately (unverified users with UpdateEmailWithoutVerification).
//
// Which flow runs depends on the config and on whether the current email is verified:
//  1. unverified + UpdateEmailWithoutVerification → change now, then send a verification link to the new address;
//  2. verified + SendChangeEmailConfirmation → ask the OLD address to confirm first (two-step);
//  3. otherwise → send a verification link to the NEW address; the change happens when it is clicked.
func (s *Service) ChangeEmail(ctx context.Context, current *dtos.SessionWithUser, in dtos.ChangeEmailInput) (*dtos.SessionWithUser, error) {
	if current == nil {
		return nil, autherr.ErrUnauthorized
	}
	ce := s.cfg.User.ChangeEmail
	// config: User.ChangeEmail.Enabled must be true
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
	// work out which flows the config allows (see the function comment)
	sendVerification := s.cfg.EmailVerification.SendVerificationEmail
	withoutVerification := !current.User.EmailVerified && ce.UpdateEmailWithoutVerification
	withConfirmation := sendVerification != nil && current.User.EmailVerified && ce.SendChangeEmailConfirmation != nil
	// checked before looking up newEmail, so a misconfiguration can't leak whether the address is taken
	if !withoutVerification && !withConfirmation && sendVerification == nil {
		return nil, autherr.ErrVerificationEmailNotEnabled
	}

	existing, err := acceptNotFound(s.repos.FindUserByEmail(ctx, newEmail))
	if err != nil {
		return nil, err
	}
	if existing != nil {
		// same work as the success path, so the response does not reveal the address is taken
		_, _ = s.emailVerificationToken(current.User.Email, newEmail, "")
		return nil, nil
	}

	// flow 1: change immediately
	if withoutVerification {
		updated, err := s.repos.UpdateUser(ctx, current.User.ID, map[string]interface{}{"Email": newEmail})
		if err != nil {
			return nil, autherr.ErrFailedToUpdateUser
		}
		s.sessions.RefreshUser(ctx, updated)
		// still send a verification link to the new address (no-op without a sender)
		if err := s.sendVerificationEmail(ctx, updated, callbackURL); err != nil {
			return nil, err
		}
		// the adapter rewrites the session cookie with the new email
		sw := *current
		sw.User = dtos.UserFromModel(updated)
		return &sw, nil
	}

	user, err := s.repos.FindUserByID(ctx, current.User.ID)
	if err != nil {
		return nil, err
	}
	// flow 2: confirmation link to the old address (handled later by verifyEmailChange)
	if withConfirmation {
		tok, err := s.emailVerificationToken(user.Email, newEmail, changeEmailConfirmation)
		if err != nil {
			return nil, err
		}
		// config: User.ChangeEmail.SendChangeEmailConfirmation sends it
		return nil, ce.SendChangeEmailConfirmation(config.ChangeEmailConfirmationData{
			User: *user, NewEmail: newEmail, URL: s.verifyURL(tok, callbackURL), Token: tok,
		}, request(ctx))
	}
	// flow 3: verification link to the new address; the email changes when it is clicked
	tok, err := s.emailVerificationToken(user.Email, newEmail, changeEmailVerification)
	if err != nil {
		return nil, err
	}
	target := *user
	target.Email = newEmail
	return nil, sendVerification(config.EmailVerificationData{User: target, URL: s.verifyURL(tok, callbackURL), Token: tok}, request(ctx))
}
