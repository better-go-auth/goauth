package auth

import (
	"context"
	"net/mail"
	"strings"
	"time"

	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/models/enums"
)

func validEmail(email string) bool {
	a, err := mail.ParseAddress(email)
	return err == nil && a.Address == email
}

// SignUpEmail mirrors better-auth's POST /sign-up/email.
func (s *Service) SignUpEmail(ctx context.Context, in dtos.SignUpEmailInput, meta Meta) (*SignUpResult, error) {
	ep := s.cfg.EmailAndPassword
	if !s.emailPasswordEnabled() || ep.DisableSignUp {
		return nil, ErrEmailPasswordSignUpDisabled
	}
	if !validEmail(in.Email) {
		return nil, autherr.ErrInvalidEmail
	}
	if in.Password == "" {
		return nil, autherr.ErrInvalidPassword
	}
	if err := s.checkPasswordLength(in.Password); err != nil {
		return nil, err
	}
	genericDuplicate := ep.RequireEmailVerification || (ep.AutoSignIn != nil && !*ep.AutoSignIn)
	email := strings.ToLower(in.Email)
	dontRemember := in.RememberMe != nil && !*in.RememberMe

	var res *SignUpResult
	var created *models.User
	err := s.inTx(ctx, func(ctx context.Context) error {
		existing, err := lookup(s.repos.FindUserByEmail(ctx, email))
		if err != nil {
			return err
		}
		if existing != nil {
			if !genericDuplicate {
				return autherr.ErrUserAlreadyExistsUseAnotherEmail
			}
			// hash anyway so both branches take the same time
			_, _ = s.passwords.Hash(in.Password)
			if ep.OnExistingUserSignUp != nil {
				_ = ep.OnExistingUserSignUp(config.ExistingUserSignUpData{User: *existing}, request(ctx))
			}
			now := time.Now().UTC()
			res = &SignUpResult{User: dtos.BetterAuthUser{
				ID: models.NewID(), Name: in.Name, Email: email, Image: in.Image,
				CreatedAt: dtos.Time(now), UpdatedAt: dtos.Time(now),
			}}
			return nil
		}

		hash, err := s.passwords.Hash(in.Password)
		if err != nil {
			return err
		}
		u := &models.User{Base: models.Base{ID: models.NewID()}}
		u.Name, u.Email, u.Image, u.Role = in.Name, email, in.Image, enums.User
		if created, err = s.repos.CreateUser(ctx, u); err != nil {
			return autherr.ErrFailedToCreateUser
		}
		_, err = s.repos.CreateAccount(ctx, &models.Account{
			Base:       models.Base{ID: models.NewID()},
			UserID:     created.ID,
			ProviderID: models.ProvCredential,
			AccountID:  created.ID,
			Password:   &hash,
		})
		if err != nil {
			return autherr.ErrFailedToCreateUser
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}

	sendOnSignUp := ep.RequireEmailVerification
	if v := s.cfg.EmailVerification.SendOnSignUp; v != nil {
		sendOnSignUp = *v
	}
	if sendOnSignUp {
		if err := s.sendVerificationEmail(ctx, created, deref(in.CallbackURL)); err != nil {
			return nil, err
		}
	}

	res = &SignUpResult{User: dtos.UserFromModel(created)}
	if genericDuplicate {
		return res, nil
	}
	sw, err := s.sessions.Create(ctx, created, meta, sessionsvc.CreateOptions{DontRemember: dontRemember})
	if err != nil {
		return nil, autherr.ErrFailedToCreateSession
	}
	res.Token, res.Session, res.DontRemember = &sw.Session.Token, sw, dontRemember
	return res, nil
}

// SignInEmail mirrors better-auth's POST /sign-in/email, plus the admin plugin's ban check.
func (s *Service) SignInEmail(ctx context.Context, in dtos.SignInEmailInput, meta Meta) (*SignInResult, error) {
	if !s.emailPasswordEnabled() {
		return nil, ErrEmailPasswordDisabled
	}
	if !validEmail(in.Email) {
		return nil, autherr.ErrInvalidEmail
	}
	user, err := lookup(s.repos.FindUserByEmail(ctx, strings.ToLower(in.Email)))
	if err != nil {
		return nil, err
	}
	var account *models.Account
	if user != nil {
		if account, err = lookup(s.repos.FindAccountByUserAndProvider(ctx, user.ID, models.ProvCredential)); err != nil {
			return nil, err
		}
	}
	if account == nil || account.Password == nil || *account.Password == "" {
		_, _ = s.passwords.Hash(in.Password)
		return nil, autherr.ErrInvalidEmailOrPassword
	}
	ok, upgraded, err := s.passwords.Verify(*account.Password, in.Password)
	if err != nil || !ok {
		return nil, autherr.ErrInvalidEmailOrPassword
	}
	if upgraded != "" {
		_, _ = s.repos.UpdateAccount(ctx, account.ID, map[string]interface{}{"Password": upgraded})
	}

	if s.cfg.EmailAndPassword.RequireEmailVerification && !user.EmailVerified {
		if s.cfg.EmailVerification.SendVerificationEmail != nil && s.cfg.EmailVerification.SendOnSignIn {
			if err := s.sendVerificationEmail(ctx, user, deref(in.CallbackURL)); err != nil {
				return nil, err
			}
		}
		return nil, autherr.ErrEmailNotVerified
	}
	if err := s.checkBan(ctx, user); err != nil {
		return nil, err
	}

	dontRemember := in.RememberMe != nil && !*in.RememberMe
	sw, err := s.sessions.Create(ctx, user, meta, sessionsvc.CreateOptions{DontRemember: dontRemember})
	if err != nil {
		if ae := autherr.AsAuthError(err); ae != nil {
			return nil, ae
		}
		return nil, autherr.ErrFailedToCreateSession
	}
	now := time.Now().UTC()
	update := map[string]interface{}{"LastLoginAt": now}
	if meta.IPAddress != "" {
		update["LastLoginIP"] = meta.IPAddress
	}
	_, _ = s.repos.UpdateUser(ctx, user.ID, update)

	return &SignInResult{
		Redirect:     in.CallbackURL != nil && *in.CallbackURL != "",
		Token:        sw.Session.Token,
		URL:          in.CallbackURL,
		User:         sw.User,
		Session:      sw,
		DontRemember: dontRemember,
	}, nil
}

// checkBan rejects banned users and lifts expired bans (better-auth admin plugin session hook).
func (s *Service) checkBan(ctx context.Context, u *models.User) error {
	if !u.Banned {
		return nil
	}
	if u.BanExpires != nil && !u.BanExpires.After(time.Now()) {
		_, err := s.repos.UpdateUser(ctx, u.ID, map[string]interface{}{"Banned": false, "BanReason": nil, "BanExpires": nil})
		return err
	}
	return ErrBannedUser
}

// SignOut revokes the session behind token; an unknown token is not an error.
func (s *Service) SignOut(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	return s.sessions.Delete(ctx, token)
}

// VerifyPassword mirrors better-auth's POST /verify-password.
func (s *Service) VerifyPassword(ctx context.Context, current *dtos.SessionWithUser, password string) error {
	if current == nil {
		return autherr.ErrUnauthorized
	}
	account, err := s.credentialAccount(ctx, current.User.ID)
	if err == autherr.ErrCredentialAccountNotFound {
		return autherr.ErrInvalidPassword
	}
	if err != nil {
		return err
	}
	if ok, _, err := s.passwords.Verify(*account.Password, password); err != nil || !ok {
		return autherr.ErrInvalidPassword
	}
	return nil
}

// credentialAccount returns the user's credential account with a password, or CREDENTIAL_ACCOUNT_NOT_FOUND.
func (s *Service) credentialAccount(ctx context.Context, userID string) (*models.Account, error) {
	a, err := lookup(s.repos.FindAccountByUserAndProvider(ctx, userID, models.ProvCredential))
	if err != nil {
		return nil, err
	}
	if a == nil || a.Password == nil || *a.Password == "" {
		return nil, autherr.ErrCredentialAccountNotFound
	}
	return a, nil
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
