package auth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/adapterrepo"
	"github.com/better-go-auth/goauth/src/app/repository/hookedrepo"
	svcint "github.com/better-go-auth/goauth/src/app/services/interfaces"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/providers/idgen"
	"github.com/better-go-auth/goauth/src/schema"
)

// UpdateUser mirrors better-auth's POST /update-user and returns the session with the new user snapshot.
//
// name and image are the endpoint's own fields; every other body key is parsed against the user schema
// (better-auth's parseUserInput(rest, "update")): goauth's profile fields, User.AdditionalFields and the
// fields of installed plugins. input:false fields (role, banned, emailVerified is a core field and ignored)
// are rejected with 400 FIELD_NOT_ALLOWED "<field> is not allowed to be set" when set to a truthy value;
// keys that are not user fields are ignored unless User.GoAuth.RejectUnknownUpdateFields is set. Email has its
// own flow (ChangeEmail).
func (s *Service) UpdateUser(ctx context.Context, current *dtos.SessionWithUser, in svcint.UpdateUserInput) (*dtos.SessionWithUser, error) {
	if current == nil {
		return nil, autherr.ErrUnauthorized
	}
	// email changes must go through ChangeEmail (verification)

	// Step 1: plugins validate and map their own body fields first (better-auth's plugin before hooks on
	// /update-user, e.g. the username plugin's username / displayUsername, phone-number's
	// PHONE_NUMBER_CANNOT_BE_UPDATED); the fields they set are trusted and skip the schema parsing below
	pluginFields := map[string]any{}
	if s.Hooks != nil {
		ev := &plugins.UserInputEvent{
			Path: plugins.UserInputUpdateUser, Body: in.Body, UserID: current.User.ID, Update: pluginFields, Request: request(ctx),
		}
		if err := s.Hooks.TriggerUserInput(ctx, ev); err != nil {
			return nil, err
		}
	}
	// the change set is keyed by field name ("displayName"); plugins may use Go field names ("Username")
	data := map[string]any{}
	for k, v := range pluginFields {
		data[userFieldName(k)] = v
	}
	// Step 2: the rest of the body (field names; Go field names from older callers are translated)
	rest := map[string]any{}
	for k, v := range in.Fields {
		name := userFieldName(k)
		// a plugin already handled this field
		if _, owned := data[name]; owned {
			continue
		}
		rest[name] = v
	}
	// config: User.GoAuth.RejectUnknownUpdateFields keeps goauth's old strict behaviour for keys that are not
	// user fields at all (better-auth ignores them)
	if s.cfg.User.GoAuth.RejectUnknownUpdateFields {
		for k := range rest {
			if !s.userField(k) {
				return nil, autherr.ErrFieldNotAllowed.WithMessage("Field " + k + " is not allowed to be set")
			}
		}
	}
	// Step 3: better-auth's parseUserInput(rest, "update"): input:false, types, validators, transforms
	parsed, err := s.internal.ParseUserInput(rest, schema.ActionUpdate)
	if err != nil {
		return nil, err
	}
	for k, v := range parsed {
		// username is unique and nullable: "" means "no username" and is stored as NULL
		if str, ok := v.(string); ok && k == "username" && str == "" {
			v = nil
		}
		data[k] = v
	}
	if in.Name != nil {
		data["name"] = *in.Name
	}
	if in.Image != nil {
		data["image"] = in.Image
	}
	if len(data) == 0 {
		return nil, ErrNoFieldsToUpdate
	}
	// Step 4: the update runs the database hooks (a hook's error reaches the client; a cancel keeps the user)
	// and refreshes the user copy of sessions cached in secondary storage
	updated, err := s.internal.UpdateUser(ctx, current.User.ID, data)
	if err != nil {
		if hookedrepo.IsHookError(err) {
			return nil, err
		}
		return nil, autherr.ErrFailedToUpdateUser
	}
	// the adapter rewrites the session cookie with the new user
	sw := *current
	sw.User = dtos.UserFromModel(updated)
	return &sw, nil
}

// userFieldName returns the field name of an update key: Go field names of models.User ("DisplayName") are
// translated, field names pass through.
func userFieldName(k string) string {
	if name, ok := adapterrepo.FieldName(schema.ModelUser, k); ok {
		return name
	}
	return k
}

// userField reports whether name is a field of the user schema.
func (s *Service) userField(name string) bool {
	if s.reg == nil {
		return false
	}
	m, ok := s.reg.Model(schema.ModelUser)
	return ok && m.Has(name)
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
	// sessions, plugin rows (UserDeleted hooks), accounts and the user, with the database delete hooks; hard
	// delete like better-auth unless config User.GoAuth.SoftDelete keeps a tombstone
	if err := s.internal.DeleteUser(ctx, user.ID); err != nil {
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
	hash, err := s.passwords.HashContext(ctx, newPassword)
	if err != nil {
		return err
	}
	_, err = s.internal.LinkAccount(ctx, &models.Account{
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
