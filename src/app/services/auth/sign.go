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

// validEmail accepts only a bare address ("a@b.co"), rejecting display-name forms like "Bob <a@b.co>".
func validEmail(email string) bool {
	a, err := mail.ParseAddress(email)
	return err == nil && a.Address == email
}

// SignUpEmail mirrors better-auth's POST /sign-up/email.
//
// Flow:
//  1. Check that sign-up is allowed and the email/password are valid.
//  2. In one transaction: if the email is taken, either fail or return a fake user (see genericDuplicate);
//     otherwise create the user and its "credential" account holding the password hash.
//  3. Optionally send the verification email.
//  4. Optionally sign the user in (create a session).
func (s *Service) SignUpEmail(ctx context.Context, in dtos.SignUpEmailInput, meta Meta) (*SignUpResult, error) {
	ep := s.cfg.EmailAndPassword
	// config: EmailAndPassword.Enabled=false or DisableSignUp=true turns this endpoint off
	if !s.emailPasswordEnabled() || ep.DisableSignUp {
		return nil, ErrEmailPasswordSignUpDisabled
	}
	if !validEmail(in.Email) {
		return nil, autherr.ErrInvalidEmail
	}
	if in.Password == "" {
		return nil, autherr.ErrInvalidPassword
	}
	// config: MinPasswordLength / MaxPasswordLength
	if err := s.checkPasswordLength(in.Password); err != nil {
		return nil, err
	}
	// config: when users must verify their email (RequireEmailVerification) or are not signed in after
	// sign-up (AutoSignIn=false), the response never contains a session. In that case a duplicate email
	// gets the same success-looking response as a new one, so attackers can't probe which emails exist.
	genericDuplicate := ep.RequireEmailVerification || (ep.AutoSignIn != nil && !*ep.AutoSignIn)
	email := strings.ToLower(in.Email)
	// rememberMe=false (explicitly) gives a 1-day session that is never extended
	dontRemember := in.RememberMe != nil && !*in.RememberMe

	var res *SignUpResult
	var created *models.User
	// user + account are created together: either both rows exist or neither
	err := s.inTx(ctx, func(ctx context.Context) error {
		existing, err := acceptNotFound(s.repos.FindUserByEmail(ctx, email))
		if err != nil {
			return err
		}
		if existing != nil {
			// the email is taken and revealing it is harmless here (the user would be signed in anyway)
			if !genericDuplicate {
				return autherr.ErrUserAlreadyExistsUseAnotherEmail
			}
			// hash anyway so both branches take the same time
			_, _ = s.passwords.Hash(in.Password)
			// config: OnExistingUserSignUp lets the app warn the real owner (e.g. "someone tried to register")
			if ep.OnExistingUserSignUp != nil {
				_ = ep.OnExistingUserSignUp(config.ExistingUserSignUpData{User: *existing}, request(ctx))
			}
			// fake user with a fresh ID, shaped exactly like a real sign-up response; nothing is stored
			now := time.Now().UTC()
			res = &SignUpResult{User: dtos.BetterAuthUser{
				ID: models.NewID(), Name: in.Name, Email: email, Image: in.Image,
				CreatedAt: dtos.Time(now), UpdatedAt: dtos.Time(now),
			}}
			return nil
		}

		// new user: hash with the configured hasher (scrypt in compat mode)
		hash, err := s.passwords.Hash(in.Password)
		if err != nil {
			return err
		}
		u := &models.User{Base: models.Base{ID: models.NewID()}}
		u.Name, u.Email, u.Image, u.Role = in.Name, email, in.Image, enums.User
		if created, err = s.repos.CreateUser(ctx, u); err != nil {
			return autherr.ErrFailedToCreateUser
		}
		// better-auth keeps passwords on a "credential" account whose accountId is the user id, not on the user row
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
	// duplicate email handled generically: return the fake user, no email, no session
	if res != nil {
		return res, nil
	}

	// config: EmailVerification.SendOnSignUp decides whether to email a verification link;
	// when unset it follows RequireEmailVerification (better-auth's default)
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
	// config: RequireEmailVerification / AutoSignIn=false → user is created but not signed in (token: null)
	if genericDuplicate {
		return res, nil
	}
	// sign the user in: new session in the DB and/or secondary storage, depending on the session config
	sw, err := s.sessions.Create(ctx, created, meta, sessionsvc.CreateOptions{DontRemember: dontRemember})
	if err != nil {
		return nil, autherr.ErrFailedToCreateSession
	}
	res.Token, res.Session, res.DontRemember = &sw.Session.Token, sw, dontRemember
	return res, nil
}

// SignInEmail mirrors better-auth's POST /sign-in/email.
//
// Flow: find the user and its credential account → verify the password (upgrading old hashes) →
// enforce email verification → create a session (plugin hooks may veto it, e.g. bans) → record the login.
// Every "wrong email" and "wrong password" case returns the same INVALID_EMAIL_OR_PASSWORD error.
func (s *Service) SignInEmail(ctx context.Context, in dtos.SignInEmailInput, meta Meta) (*SignInResult, error) {
	// config: EmailAndPassword.Enabled=false turns email/password sign-in off
	if !s.emailPasswordEnabled() {
		return nil, ErrEmailPasswordDisabled
	}
	if !validEmail(in.Email) {
		return nil, autherr.ErrInvalidEmail
	}
	user, err := acceptNotFound(s.repos.FindUserByEmail(ctx, strings.ToLower(in.Email)))
	if err != nil {
		return nil, err
	}
	// the password lives on the user's "credential" account (users who only use OAuth have none)
	var account *models.Account
	if user != nil {
		if account, err = acceptNotFound(s.repos.FindAccountByUserAndProvider(ctx, user.ID, models.ProvCredential)); err != nil {
			return nil, err
		}
	}
	if account == nil || account.Password == nil || *account.Password == "" {
		// unknown user or no password: still spend the hashing time so response timing doesn't reveal it
		_, _ = s.passwords.Hash(in.Password)
		return nil, autherr.ErrInvalidEmailOrPassword
	}
	// Verify accepts scrypt, bcrypt and argon2 hashes; with RehashPasswords it also returns a new hash
	// in the default format when the stored one is older
	ok, upgraded, err := s.passwords.Verify(*account.Password, in.Password)
	if err != nil || !ok {
		return nil, autherr.ErrInvalidEmailOrPassword
	}
	// config: EmailAndPassword.RehashPasswords → store the upgraded hash (best effort, sign-in still succeeds)
	if upgraded != "" {
		_, _ = s.repos.UpdateAccount(ctx, account.ID, map[string]interface{}{"Password": upgraded})
	}

	// config: RequireEmailVerification blocks unverified users. The check runs after the password check,
	// so only the real owner learns the email is unverified.
	if s.cfg.EmailAndPassword.RequireEmailVerification && !user.EmailVerified {
		// config: EmailVerification.SendOnSignIn re-sends the verification link on each blocked attempt
		if s.cfg.EmailVerification.SendVerificationEmail != nil && s.cfg.EmailVerification.SendOnSignIn {
			if err := s.sendVerificationEmail(ctx, user, deref(in.CallbackURL)); err != nil {
				return nil, err
			}
		}
		return nil, autherr.ErrEmailNotVerified
	}

	// rememberMe=false (explicitly) gives a 1-day session that is never extended
	dontRemember := in.RememberMe != nil && !*in.RememberMe
	sw, err := s.sessions.Create(ctx, user, meta, sessionsvc.CreateOptions{DontRemember: dontRemember})
	if err != nil {
		// a BeforeSessionCreate hook may reject the session with its own code (e.g. the admin plugin's BANNED_USER)
		if ae := autherr.AsAuthError(err); ae != nil {
			return nil, ae
		}
		return nil, autherr.ErrFailedToCreateSession
	}
	// goauth extra: remember when and from where the user last signed in (best effort)
	now := time.Now().UTC()
	update := map[string]interface{}{"LastLoginAt": now}
	if meta.IPAddress != "" {
		update["LastLoginIP"] = meta.IPAddress
	}
	_, _ = s.repos.UpdateUser(ctx, user.ID, update)

	// better-auth's response: redirect=true tells the client to follow URL (the callbackURL it sent)
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
// Ban fields (Banned, BanReason, BanExpires) are set by the admin plugin.
// func (s *Service) checkBan(ctx context.Context, u *models.User) error {
// 	if !u.Banned {
// 		return nil
// 	}
// 	// BanExpires nil = permanent ban; a date in the past = the ban is over, so clear it and allow sign-in
// 	if u.BanExpires != nil && !u.BanExpires.After(time.Now()) {
// 		_, err := s.repos.UpdateUser(ctx, u.ID, map[string]interface{}{"Banned": false, "BanReason": nil, "BanExpires": nil})
// 		return err
// 	}
// 	return ErrBannedUser
// }

// SignOut revokes the session behind token; an unknown token is not an error.
// The session manager removes it from the DB and/or secondary storage; the adapter clears the cookies.
func (s *Service) SignOut(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	return s.sessions.Delete(ctx, token)
}

// VerifyPassword mirrors better-auth's POST /verify-password: checks the signed-in user's password
// (used by apps before sensitive actions). A user without a password gets INVALID_PASSWORD, as in better-auth.
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

// credentialAccount returns the user's credential account with a password, or CREDENTIAL_ACCOUNT_NOT_FOUND
// (e.g. a user who only signs in with Google has no credential account).
func (s *Service) credentialAccount(ctx context.Context, userID string) (*models.Account, error) {
	a, err := acceptNotFound(s.repos.FindAccountByUserAndProvider(ctx, userID, models.ProvCredential))
	if err != nil {
		return nil, err
	}
	if a == nil || a.Password == nil || *a.Password == "" {
		return nil, autherr.ErrCredentialAccountNotFound
	}
	return a, nil
}

// deref returns the string behind p, or "" when p is nil (optional request fields).
func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
