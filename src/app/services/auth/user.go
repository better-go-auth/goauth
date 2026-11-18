package auth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	svcint "github.com/better-go-auth/goauth/src/app/services/interfaces"
	"github.com/better-go-auth/goauth/src/app/services/userdelete"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/providers/idgen"
)

// updatableUserFields are the goauth profile fields update-user accepts besides name and image
// (better-auth's user.additionalFields). Role, ban and verification fields are deliberately absent.
var updatableUserFields = map[string]bool{
	"FirstName": true, "LastName": true, "Username": true, "DisplayName": true, "Bio": true,
	"DateOfBirth": true, "Gender": true, "Locale": true, "Timezone": true,
}

// protectedUserField is a better-auth schema field with `input: false` (never set by update-user).
type protectedUserField struct {
	// json is the better-auth field name.
	json string
	// plugin fields only exist while their plugin is installed (dtos.UserFieldInstalled); core fields always.
	plugin bool
	// hasDefault: better-auth silently skips input:false fields that have a defaultValue; the others fail
	// with "<field> is not allowed to be set" when the value is truthy.
	hasDefault bool
}

// protectedUserFields maps Go field names to better-auth's input:false user fields.
var protectedUserFields = map[string]protectedUserField{
	"EmailVerified":       {json: "emailVerified", hasDefault: true},
	"CreatedAt":           {json: "createdAt", hasDefault: true},
	"UpdatedAt":           {json: "updatedAt", hasDefault: true},
	"Role":                {json: dtos.FieldRole, plugin: true},
	"Banned":              {json: dtos.FieldBanned, plugin: true, hasDefault: true},
	"BanReason":           {json: dtos.FieldBanReason, plugin: true},
	"BanExpires":          {json: dtos.FieldBanExpires, plugin: true},
	"PhoneNumberVerified": {json: dtos.FieldPhoneNumberVerified, plugin: true},
	"TwoFactorEnabled":    {json: dtos.FieldTwoFactorEnabled, plugin: true, hasDefault: true},
	"IsAnonymous":         {json: dtos.FieldIsAnonymous, plugin: true, hasDefault: true},
}

// fieldNotAllowedError is better-auth's parseInputData error for an input:false field. better-call derives
// the code from the message (upper case, spaces to "_").
func fieldNotAllowedError(field string) error {
	msg := field + " is not allowed to be set"
	code := strings.ToUpper(strings.ReplaceAll(msg, " ", "_"))
	return autherr.Err(http.StatusBadRequest, code, msg)
}

// UpdateUser mirrors better-auth's POST /update-user and returns the session with the new user snapshot.
//
// Only name, image and the allowlisted profile fields can be changed. Email has its own flow (ChangeEmail),
// and role/ban/verification fields are never writable here.
func (s *Service) UpdateUser(ctx context.Context, current *dtos.SessionWithUser, in svcint.UpdateUserInput) (*dtos.SessionWithUser, error) {
	if current == nil {
		return nil, autherr.ErrUnauthorized
	}
	// email changes must go through ChangeEmail (verification)

	// plugins validate and map their own body fields first (e.g. the username plugin's
	// username / displayUsername); the fields they set are trusted and skip the allowlist below
	pluginFields := map[string]any{}
	if s.Hooks != nil {
		ev := &plugins.UserInputEvent{
			Path: plugins.UserInputUpdateUser, Body: in.Body, UserID: current.User.ID, Update: pluginFields, Request: request(ctx),
		}
		if err := s.Hooks.TriggerUserInput(ctx, ev); err != nil {
			return nil, err
		}
	}
	// the update map is keyed by Go field names, which both repositories understand
	data := map[string]any{}
	for k, v := range pluginFields {
		data[k] = v
	}
	for k, v := range in.Fields {
		// a plugin already handled this field
		if _, owned := pluginFields[k]; owned {
			continue
		}
		// fields outside the allowlist are never written (blocks e.g. {"role": "admin"})
		if !updatableUserFields[k] {
			// better-auth's input:false fields: skipped when they have a default, rejected when set
			if pf, ok := protectedUserFields[k]; ok && (!pf.plugin || dtos.UserFieldInstalled(pf.json)) {
				if !pf.hasDefault && plugins.IsTruthy(v) {
					return nil, fieldNotAllowedError(pf.json)
				}
				continue
			}
			// config: User.GoAuth.RejectUnknownUpdateFields keeps goauth's old strict behaviour
			if s.cfg.User.GoAuth.RejectUnknownUpdateFields {
				return nil, autherr.ErrFieldNotAllowed.WithMessage("Field " + k + " is not allowed to be set")
			}
			// better-auth ignores keys that are not in the user schema
			continue
		}
		// username is unique and nullable: "" means "no username" and is stored as NULL
		if str, ok := v.(string); ok && k == "Username" && str == "" {
			v = nil
		}
		data[k] = v
	}
	if in.Name != nil {
		data["Name"] = *in.Name
	}
	if in.Image != nil {
		data["Image"] = in.Image
	}
	if len(data) == 0 {
		return nil, ErrNoFieldsToUpdate
	}
	updated, err := s.repos.UpdateUser(ctx, current.User.ID, data)
	if err != nil {
		return nil, autherr.ErrFailedToUpdateUser
	}
	// sessions cached in secondary storage hold a copy of the user; update it everywhere
	s.sessionMgr.RefreshUser(ctx, updated)
	// the adapter rewrites the session cookie with the new user
	sw := *current
	sw.User = dtos.UserFromModel(updated)
	return &sw, nil
}

// deleteAccountIdentifier is better-auth's verification identifier for delete-account confirmation tokens.
func deleteAccountIdentifier(token string) string { return "delete-account-" + token }

// Messages better-auth returns from delete-user.
const (
	MsgUserDeleted           = "User deleted"
	MsgVerificationEmailSent = "Verification email sent"
)

// DeleteUser mirrors better-auth's POST /delete-user. It returns better-auth's message:
// "User deleted", or "Verification email sent" when a confirmation link was emailed instead.
//
// Flow: check the feature is on → if a password is sent, check it → a confirmation token in the body
// deletes via DeleteUserCallback → with SendDeleteAccountVerification configured, email a link and stop →
// otherwise require a password or a fresh session → delete.
func (s *Service) DeleteUser(ctx context.Context, current *dtos.SessionWithUser, in dtos.DeleteUserInput) (string, error) {
	if current == nil {
		return "", autherr.ErrUnauthorized
	}
	opts := s.cfg.User.DeleteUser
	// config: User.DeleteUser.Enabled; better-auth answers 404 when it's off, as if the route didn't exist
	if !opts.Enabled {
		return "", ErrDeleteUserDisabled
	}
	if in.Password != nil {
		// a password was sent: it must match the credential account
		account, err := s.credentialAccount(ctx, current.User.ID)
		if err != nil {
			return "", err
		}
		if ok, _, err := s.passwords.Verify(*account.Password, *in.Password); err != nil || !ok {
			return "", autherr.ErrInvalidPassword
		}
	}
	// the client may post the emailed token here instead of following the callback link
	if in.Token != nil && *in.Token != "" {
		if err := s.DeleteUserCallback(ctx, current, *in.Token); err != nil {
			return "", err
		}
		return MsgUserDeleted, nil
	}
	// config: User.DeleteUser.SendDeleteAccountVerification → email a confirmation link; nothing is deleted yet
	if send := opts.SendDeleteAccountVerification; send != nil {
		user, err := s.repos.FindUserByID(ctx, current.User.ID)
		if err != nil {
			return "", autherr.ErrUserNotFound
		}
		tok := idgen.GenerateToken()
		_, err = s.repos.UpsertVerificationValue(ctx, &models.Verification{
			Base:       models.Base{ID: models.NewID()},
			Identifier: deleteAccountIdentifier(tok),
			Value:      user.ID,
			// config: User.DeleteUser.DeleteTokenExpiresIn (default 24h)
			ExpiresAt: time.Now().Add(opts.DeleteTokenExpiresIn).UTC(),
		})
		if err != nil {
			return "", autherr.ErrFailedToCreateVerification
		}
		callbackURL := "/"
		if in.CallbackURL != nil && *in.CallbackURL != "" {
			callbackURL = *in.CallbackURL
		}
		link := s.baseURL(ctx) + "/delete-user/callback?token=" + tok + "&callbackURL=" + url.QueryEscape(callbackURL)
		// config: Advanced.BackgroundTasks.Handler runs the sender without blocking the response
		data := config.DeleteAccountVerificationData{User: *user, URL: link, Token: tok}
		if err := s.cfg.RunInBackgroundOrAwait(ctx, func(ctx context.Context) error { return send(data, request(ctx)) }); err != nil {
			return "", err
		}
		return MsgVerificationEmailSent, nil
	}
	// no password: config Session.FreshAge (default 1 day) requires a recently created session
	if in.Password == nil && s.sessionMgr.Config().FreshAge != 0 && !s.sessionMgr.IsFresh(current) {
		return "", autherr.ErrSessionExpired
	}
	if err := s.deleteUserNow(ctx, current.User.ID); err != nil {
		return "", err
	}
	return MsgUserDeleted, nil
}

// DeleteUserCallback backs better-auth's GET /delete-user/callback: the link from the confirmation email.
// The token is consumed first, so it works once; a token issued for another user is rejected (and burned).
func (s *Service) DeleteUserCallback(ctx context.Context, current *dtos.SessionWithUser, token string) error {
	if !s.cfg.User.DeleteUser.Enabled {
		return ErrDeleteUserDisabled
	}
	if current == nil {
		return autherr.ErrFailedToGetUserInfo.WithStatus(http.StatusNotFound)
	}
	v, err := s.repos.ConsumeVerificationValue(ctx, deleteAccountIdentifier(token))
	if err != nil && !isNotFound(err) {
		return err
	}
	if v == nil || v.Value != current.User.ID {
		return autherr.ErrInvalidToken.WithStatus(http.StatusNotFound)
	}
	return s.deleteUserNow(ctx, current.User.ID)
}

// deleteUserNow runs BeforeDelete, deletes the accounts and the user, signs the user out everywhere,
// then runs AfterDelete.
func (s *Service) deleteUserNow(ctx context.Context, userID string) error {
	opts := s.cfg.User.DeleteUser
	user, err := s.repos.FindUserByID(ctx, userID)
	if err != nil {
		return autherr.ErrUserNotFound
	}
	// config: User.DeleteUser.BeforeDelete can veto the deletion (e.g. the user still owns an organization)
	if opts.BeforeDelete != nil {
		if err := opts.BeforeDelete(*user, request(ctx)); err != nil {
			return err
		}
	}
	// sessions, plugin rows (UserDeleted hooks), accounts and the user; hard delete like better-auth
	// unless config User.GoAuth.SoftDelete keeps a tombstone
	err = userdelete.Run(ctx, userdelete.Deps{
		Soft:           s.cfg.User.GoAuth.SoftDelete,
		RevokeSessions: s.sessionMgr.DeleteUserSessions,
		RemoveRows:     s.removeUserRows,
		Hooks:          s.Hooks,
	}, user.ID)
	if err != nil {
		return err
	}
	// config: User.DeleteUser.AfterDelete for cleanup in the app (files, audit log, ...)
	if opts.AfterDelete != nil {
		return opts.AfterDelete(*user, request(ctx))
	}
	return nil
}

// SetPassword mirrors better-auth's server-only setPassword: gives a user without a password
// (e.g. OAuth-only) a credential account. It is not exposed over HTTP.
func (s *Service) SetPassword(ctx context.Context, userID, newPassword string) error {
	// config: MinPasswordLength / MaxPasswordLength
	if err := s.checkPasswordLength(newPassword); err != nil {
		return err
	}
	if _, err := s.credentialAccount(ctx, userID); err == nil {
		return autherr.ErrPasswordAlreadySet
	} else if err != autherr.ErrCredentialAccountNotFound {
		return err
	}
	hash, err := s.passwords.Hash(newPassword)
	if err != nil {
		return err
	}
	_, err = s.repos.CreateAccount(ctx, &models.Account{
		Base:       models.Base{ID: models.NewID()},
		UserID:     userID,
		ProviderID: models.ProvCredential,
		AccountID:  userID,
		Password:   &hash,
	})
	return err
}

// ListAccounts mirrors better-auth's GET /list-accounts: the user's sign-in methods
// (credential, google, ...), without any tokens or password hashes.
func (s *Service) ListAccounts(ctx context.Context, current *dtos.SessionWithUser) ([]dtos.AccountResponse, error) {
	if current == nil {
		return nil, autherr.ErrUnauthorized
	}
	accounts, err := s.repos.FindAccounts(ctx, current.User.ID)
	if err != nil {
		return nil, err
	}
	out := make([]dtos.AccountResponse, 0, len(accounts))
	for _, a := range accounts {
		// OAuth scopes are stored as one comma-separated string; the response wants a list
		scopes := []string{}
		if a.Scope != nil && *a.Scope != "" {
			scopes = strings.Split(*a.Scope, ",")
		}
		out = append(out, dtos.AccountResponse{
			ID: a.ID, ProviderID: a.ProviderID.S(), AccountID: a.AccountID, UserID: a.UserID, Scopes: scopes,
			CreatedAt: dtos.Time(a.CreatedAt), UpdatedAt: dtos.Time(a.UpdatedAt),
		})
	}
	return out, nil
}

// UnlinkAccount mirrors better-auth's POST /unlink-account: removes one sign-in method from the user.
func (s *Service) UnlinkAccount(ctx context.Context, current *dtos.SessionWithUser, in dtos.UnlinkAccountInput) error {
	if current == nil {
		return autherr.ErrUnauthorized
	}
	accounts, err := s.repos.FindAccounts(ctx, current.User.ID)
	if err != nil {
		return err
	}
	// config: Account.AccountLinking.AllowUnlinkingAll; by default the last sign-in method can't be removed,
	// otherwise the user could never sign in again
	if len(accounts) == 1 && !s.cfg.Account.AccountLinking.AllowUnlinkingAll {
		return autherr.ErrFailedToUnlinkLastAccount
	}
	// match by provider, and by the provider's account id when the client sends one
	var match *models.Account
	for i := range accounts {
		a := &accounts[i]
		if a.ProviderID.S() == in.ProviderID && (in.AccountID == "" || a.AccountID == in.AccountID) {
			match = a
			break
		}
	}
	if match == nil {
		return autherr.ErrAccountNotFound
	}
	return s.repos.DeleteAccount(ctx, match.ID)
}

// removeUserRows deletes the user's accounts and the user row in one transaction (soft: tombstone).
func (s *Service) removeUserRows(ctx context.Context, userID string, soft bool) error {
	return s.inTx(ctx, func(ctx context.Context) error {
		if err := s.repos.DeleteAccounts(ctx, userID); err != nil {
			return err
		}
		if soft {
			return s.repos.SoftDeleteUser(ctx, userID)
		}
		return s.repos.DeleteUser(ctx, userID)
	})
}
