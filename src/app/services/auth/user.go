package auth

import (
	"context"
	"strings"

	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
)

// updatableUserFields are the goauth profile fields update-user accepts besides name and image
// (better-auth's user.additionalFields). Role, ban and verification fields are deliberately absent.
var updatableUserFields = map[string]bool{
	"FirstName": true, "LastName": true, "Username": true, "DisplayName": true, "Bio": true,
	"DateOfBirth": true, "Gender": true, "Locale": true, "Timezone": true,
}

// UpdateUser mirrors better-auth's POST /update-user and returns the session with the new user snapshot.
func (s *Service) UpdateUser(ctx context.Context, current *dtos.SessionWithUser, in UpdateUserInput) (*dtos.SessionWithUser, error) {
	if current == nil {
		return nil, autherr.ErrUnauthorized
	}
	if in.Email != nil {
		return nil, autherr.ErrEmailCanNotBeUpdated
	}
	data := map[string]interface{}{}
	for k, v := range in.Fields {
		if !updatableUserFields[k] {
			return nil, autherr.ErrFieldNotAllowed.WithMessage("Field " + k + " is not allowed to be set")
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
	s.sessions.RefreshUser(ctx, updated)
	sw := *current
	sw.User = dtos.UserFromModel(updated)
	return &sw, nil
}

// DeleteUser mirrors better-auth's POST /delete-user without the emailed confirmation flow.
// Without a password the session must be fresh.
func (s *Service) DeleteUser(ctx context.Context, current *dtos.SessionWithUser, password *string) error {
	if current == nil {
		return autherr.ErrUnauthorized
	}
	opts := s.cfg.User.DeleteUser
	if !opts.Enabled {
		return ErrDeleteUserDisabled
	}
	if password != nil {
		account, err := s.credentialAccount(ctx, current.User.ID)
		if err != nil {
			return err
		}
		if ok, _, err := s.passwords.Verify(*account.Password, *password); err != nil || !ok {
			return autherr.ErrInvalidPassword
		}
	} else if s.sessions.Config().FreshAge != 0 && !s.sessions.IsFresh(current) {
		return autherr.ErrSessionExpired
	}
	user, err := s.repos.FindUserByID(ctx, current.User.ID)
	if err != nil {
		return autherr.ErrUserNotFound
	}
	if opts.BeforeDelete != nil {
		if err := opts.BeforeDelete(*user, request(ctx)); err != nil {
			return err
		}
	}
	err = s.inTx(ctx, func(ctx context.Context) error {
		if err := s.repos.DeleteAccounts(ctx, user.ID); err != nil {
			return err
		}
		return s.repos.DeleteUser(ctx, user.ID)
	})
	if err != nil {
		return err
	}
	if err := s.sessions.DeleteUserSessions(ctx, user.ID); err != nil {
		return err
	}
	if opts.AfterDelete != nil {
		return opts.AfterDelete(*user, request(ctx))
	}
	return nil
}

// ListAccounts mirrors better-auth's GET /list-accounts.
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
		scopes := []string{}
		if a.Scope != nil && *a.Scope != "" {
			scopes = strings.Split(*a.Scope, ",")
		}
		out = append(out, dtos.AccountResponse{
			ID: a.ID, ProviderID: a.ProviderID.S(), AccountID: a.AccountID, UserID: a.UserID, Scopes: scopes,
			CreatedAt: dtos.FormatTime(a.CreatedAt), UpdatedAt: dtos.FormatTime(a.UpdatedAt),
		})
	}
	return out, nil
}

// UnlinkAccount mirrors better-auth's POST /unlink-account.
func (s *Service) UnlinkAccount(ctx context.Context, current *dtos.SessionWithUser, in dtos.UnlinkAccountInput) error {
	if current == nil {
		return autherr.ErrUnauthorized
	}
	accounts, err := s.repos.FindAccounts(ctx, current.User.ID)
	if err != nil {
		return err
	}
	if len(accounts) == 1 && !s.cfg.Account.AccountLinking.AllowUnlinkingAll {
		return autherr.ErrFailedToUnlinkLastAccount
	}
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
	return s.repos.DeleteAccountByUserAndProvider(ctx, current.User.ID, match.ProviderID.S())
}
