// Package internaladapter is goauth's port of better-auth's internalAdapter (better-auth/dist/db/
// internal-adapter.mjs): the one write path for users, sessions, accounts and verifications used by the core
// endpoints and by plugins (through InitContext.Internal / pluginkit.Kit.Internal).
//
// The repositories it writes through are wrapped by hookedrepo, so the database hooks (AuthConfig.
// DatabaseHooks, plugin hooks and the HookRegistry's Before/AfterUserCreate) run on every write; on top of
// that the adapter fills ids, timestamps and lower-cased emails, keeps the user copy of sessions cached in
// secondary storage up to date, runs the full user deletion (sessions, plugin rows, accounts, user) and
// parses request bodies with the schema registry (additionalFields).
package internaladapter

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/adapterrepo"
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	svcint "github.com/better-go-auth/goauth/src/app/services/interfaces"
	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	"github.com/better-go-auth/goauth/src/app/services/userdelete"
	"github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/dbhooks"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	"github.com/better-go-auth/goauth/src/models"
	authdtos "github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/schema"
)

// Deps are the collaborators of Adapter.
type Deps struct {
	// Repos are the repositories, already wrapped with the database hooks (hookedrepo.Wrap).
	Repos repo_interfaces.IAuthRepos
	// Sessions is the session manager (secondary storage, cookie-cache-independent session store).
	Sessions *sessionsvc.Manager
	// Schema is the schema registry (input parsing, field names).
	Schema *schema.Registry
	// Tx groups multi-row writes; nil runs them without a transaction. Wrap it with dbhooks.WrapTx so after
	// hooks wait for the commit.
	Tx interfaces.ITransactionManager
	// Hooks receive UserDeleted (plugin rows of a deleted user).
	Hooks plugins.HookRegistry
	// SoftDelete keeps deleted users as tombstones (config User.GoAuth.SoftDelete).
	SoftDelete bool
	// GenerateID creates record ids (nil = models.NewID).
	GenerateID func() string
}

// Adapter implements svcint.IInternalAdapter.
type Adapter struct {
	d Deps
}

var _ svcint.IInternalAdapter = (*Adapter)(nil)

// New builds the internal adapter.
func New(d Deps) *Adapter {
	return &Adapter{d: d}
}

// newID returns a new record id.
func (a *Adapter) newID() string {
	if a.d.GenerateID != nil {
		return a.d.GenerateID()
	}
	return models.NewID()
}

// Schema returns the schema registry.
func (a *Adapter) Schema() *schema.Registry { return a.d.Schema }

// Transaction runs fn in a transaction when a transaction manager is configured.
func (a *Adapter) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	if a.d.Tx == nil {
		// without a transaction manager after hooks still wait until fn returned successfully
		qctx, end := dbhooks.WithAfterQueue(ctx)
		err := fn(qctx)
		if hookErr := end(ctx, err == nil); err == nil {
			err = hookErr
		}
		return err
	}
	return a.d.Tx.Transaction(ctx, fn)
}

// IsCancelled reports whether err comes from a database Before hook that cancelled the operation.
func (a *Adapter) IsCancelled(err error) bool { return IsCancelled(err) }

// IsCancelled reports whether err comes from a database Before hook that cancelled the operation
// (better-auth's createWithHooks returning null).
func IsCancelled(err error) bool { return dbhooks.IsCancel(err) }

// ─── Users ───────────────────────────────────────────────────────────────────

// CreateUser is better-auth's internalAdapter.createUser.
func (a *Adapter) CreateUser(ctx context.Context, user *models.User) (*models.User, error) {
	if user == nil {
		return nil, errors.New("internaladapter: user is required")
	}
	// Step 1: id, timestamps and the lower-cased email (better-auth's createUser data)
	if user.ID == "" {
		user.ID = a.newID()
	}
	now := time.Now().UTC()
	if user.CreatedAt.IsZero() {
		user.CreatedAt = now
	}
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = now
	}
	user.Email = strings.ToLower(strings.TrimSpace(user.Email))
	// Step 2: insert with the user create hooks
	return a.d.Repos.CreateUser(ctx, user)
}

// CreateOAuthUser is better-auth's internalAdapter.createOAuthUser: the user and its first account in one
// transaction.
func (a *Adapter) CreateOAuthUser(ctx context.Context, user *models.User, account *models.Account) (*models.User, *models.Account, error) {
	var created *models.User
	var linked *models.Account
	err := a.Transaction(ctx, func(ctx context.Context) error {
		// Step 1: the user
		var err error
		if created, err = a.CreateUser(ctx, user); err != nil {
			return err
		}
		// Step 2: the account pointing at it
		account.UserID = created.ID
		linked, err = a.LinkAccount(ctx, account)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return created, linked, nil
}

// UpdateUser is better-auth's internalAdapter.updateUser: the update with hooks, then refreshUserSessions.
func (a *Adapter) UpdateUser(ctx context.Context, userID string, data map[string]any) (*models.User, error) {
	// Step 1: field names, values of the field's type, emails lower-cased; keys that are not user fields
	// (or fields of plugins that aren't installed) are dropped like better-auth's adapter does
	changes, err := a.fieldValues(schema.ModelUser, data)
	if err != nil {
		return nil, err
	}
	if e, ok := changes["email"].(string); ok {
		changes["email"] = strings.ToLower(strings.TrimSpace(e))
	}
	// Step 2: update with the user update hooks
	updated, err := a.d.Repos.UpdateUser(ctx, userID, changes)
	if err != nil {
		return nil, err
	}
	// Step 3: sessions cached in secondary storage hold a copy of the user
	if a.d.Sessions != nil {
		a.d.Sessions.RefreshUser(ctx, updated)
	}
	return updated, nil
}

// FindUserByID is better-auth's internalAdapter.findUserById.
func (a *Adapter) FindUserByID(ctx context.Context, userID string) (*models.User, error) {
	return a.d.Repos.FindUserByID(ctx, userID)
}

// DeleteUser is better-auth's internalAdapter.deleteUser plus the plugin cleanup: sessions, plugin rows
// (UserDeleted hooks), accounts and the user row (a tombstone with User.GoAuth.SoftDelete).
func (a *Adapter) DeleteUser(ctx context.Context, userID string) error {
	return userdelete.Run(ctx, userdelete.Deps{
		Soft:           a.d.SoftDelete,
		RevokeSessions: a.DeleteUserSessions,
		RemoveRows: func(ctx context.Context, userID string, soft bool) error {
			return a.Transaction(ctx, func(ctx context.Context) error {
				// Step 1: the accounts (account delete hooks run per account)
				if err := a.d.Repos.DeleteAccounts(ctx, userID); err != nil {
					return err
				}
				// Step 2: the user row (user delete hooks)
				if soft {
					return a.d.Repos.SoftDeleteUser(ctx, userID)
				}
				return a.d.Repos.DeleteUser(ctx, userID)
			})
		},
		Hooks: a.d.Hooks,
	}, userID)
}

// ─── Sessions ────────────────────────────────────────────────────────────────

// CreateSession is better-auth's internalAdapter.createSession.
func (a *Adapter) CreateSession(ctx context.Context, user *models.User, meta svcint.SessionMeta, opts svcint.SessionCreateOptions) (*authdtos.SessionWithUser, error) {
	if a.d.Sessions == nil {
		return nil, errors.New("internaladapter: no session manager")
	}
	return a.d.Sessions.Create(ctx, user, meta, opts)
}

// UpdateSession is better-auth's internalAdapter.updateSession.
func (a *Adapter) UpdateSession(ctx context.Context, current *authdtos.SessionWithUser, data map[string]any) (*authdtos.SessionWithUser, error) {
	if a.d.Sessions == nil || current == nil {
		return nil, errors.New("internaladapter: no session")
	}
	return a.d.Sessions.Update(ctx, current, data)
}

// DeleteSession is better-auth's internalAdapter.deleteSession.
func (a *Adapter) DeleteSession(ctx context.Context, token string) error {
	if a.d.Sessions == nil {
		return a.d.Repos.DeleteSession(ctx, token)
	}
	return a.d.Sessions.Delete(ctx, token)
}

// DeleteUserSessions is better-auth's internalAdapter.deleteUserSessions.
func (a *Adapter) DeleteUserSessions(ctx context.Context, userID string) error {
	if a.d.Sessions == nil {
		return a.d.Repos.DeleteUserSessions(ctx, userID)
	}
	return a.d.Sessions.DeleteUserSessions(ctx, userID)
}

// ─── Accounts ────────────────────────────────────────────────────────────────

// LinkAccount is better-auth's internalAdapter.linkAccount / createAccount.
func (a *Adapter) LinkAccount(ctx context.Context, account *models.Account) (*models.Account, error) {
	if account == nil {
		return nil, errors.New("internaladapter: account is required")
	}
	// Step 1: id and timestamps
	if account.ID == "" {
		account.ID = a.newID()
	}
	now := time.Now().UTC()
	if account.CreatedAt.IsZero() {
		account.CreatedAt = now
	}
	if account.UpdatedAt.IsZero() {
		account.UpdatedAt = now
	}
	// Step 2: insert with the account create hooks
	return a.d.Repos.CreateAccount(ctx, account)
}

// UpdateAccount is better-auth's internalAdapter.updateAccount.
func (a *Adapter) UpdateAccount(ctx context.Context, accountID string, data map[string]any) (*models.Account, error) {
	return a.d.Repos.UpdateAccount(ctx, accountID, data)
}

// UpdatePassword is better-auth's internalAdapter.updatePassword: the credential account's password hash.
func (a *Adapter) UpdatePassword(ctx context.Context, userID, hash string) error {
	acc, err := a.d.Repos.FindAccountByUserAndProvider(ctx, userID, models.ProvCredential)
	if err != nil {
		return err
	}
	_, err = a.d.Repos.UpdateAccount(ctx, acc.ID, map[string]any{"password": hash})
	return err
}

// DeleteAccount is better-auth's internalAdapter.deleteAccount.
func (a *Adapter) DeleteAccount(ctx context.Context, accountID string) error {
	return a.d.Repos.DeleteAccount(ctx, accountID)
}

// DeleteAccounts is better-auth's internalAdapter.deleteAccounts.
func (a *Adapter) DeleteAccounts(ctx context.Context, userID string) error {
	return a.d.Repos.DeleteAccounts(ctx, userID)
}

// ─── Verifications ───────────────────────────────────────────────────────────

// CreateVerificationValue is better-auth's internalAdapter.createVerificationValue.
func (a *Adapter) CreateVerificationValue(ctx context.Context, v *models.Verification) (*models.Verification, error) {
	if v == nil {
		return nil, errors.New("internaladapter: verification is required")
	}
	if v.ID == "" {
		v.ID = a.newID()
	}
	return a.d.Repos.UpsertVerificationValue(ctx, v)
}

// FindVerificationValue is better-auth's internalAdapter.findVerificationValue.
func (a *Adapter) FindVerificationValue(ctx context.Context, identifier string) (*models.Verification, error) {
	return a.d.Repos.FindVerificationValue(ctx, identifier)
}

// ConsumeVerificationValue is better-auth's internalAdapter.consumeVerificationValue.
func (a *Adapter) ConsumeVerificationValue(ctx context.Context, identifier string) (*models.Verification, error) {
	return a.d.Repos.ConsumeVerificationValue(ctx, identifier)
}

// DeleteVerificationByIdentifier is better-auth's internalAdapter.deleteVerificationByIdentifier.
func (a *Adapter) DeleteVerificationByIdentifier(ctx context.Context, identifier string) error {
	return a.d.Repos.DeleteVerificationByIdentifier(ctx, identifier)
}

// ─── Schema ──────────────────────────────────────────────────────────────────

// ParseUserInput is better-auth's parseUserInput.
func (a *Adapter) ParseUserInput(data map[string]any, action schema.Action) (map[string]any, error) {
	if a.d.Schema == nil {
		return map[string]any{}, nil
	}
	return a.d.Schema.ParseInput(schema.ModelUser, data, action)
}

// ParseSessionInput is better-auth's parseSessionInput.
func (a *Adapter) ParseSessionInput(data map[string]any, action schema.Action) (map[string]any, error) {
	if a.d.Schema == nil {
		return map[string]any{}, nil
	}
	return a.d.Schema.ParseInput(schema.ModelSession, data, action)
}

// SetUserFields writes field-name values onto user (see svcint.IInternalAdapter).
func (a *Adapter) SetUserFields(user *models.User, data map[string]any) error {
	return SetFields(a.d.Schema, schema.ModelUser, user, data)
}

// SetFields writes field-name values onto rec (a *models.User, *models.Session, *models.Account or
// *models.Verification): values are converted to the field's logical type, struct fields are assigned and
// the other fields of the model go to Extra. Keys that are not fields of the model are ignored; a value
// that doesn't fit its field is a 400 VALIDATION_ERROR.
func SetFields(reg *schema.Registry, model string, rec schema.ExtraSetter, data map[string]any) error {
	var m *schema.ResolvedModel
	if reg != nil {
		m, _ = reg.Model(model)
	}
	for k, v := range data {
		// Step 1: the canonical Go value of the field's type
		if m != nil {
			f, ok := m.Field(k)
			if !ok {
				continue
			}
			nv, err := schema.Normalize(f.Type, v)
			if err != nil {
				return autherr.ErrValidationError.WithMessage("[body." + k + "] " + err.Error())
			}
			v = nv
		}
		// Step 2: a struct field, else Extra
		static, err := adapterrepo.SetGoField(rec, model, k, v)
		if err != nil {
			return autherr.ErrValidationError.WithMessage(err.Error())
		}
		if !static && (m != nil || v != nil) {
			rec.SetExtra(k, v)
		}
	}
	return nil
}

// TypedHooks runs the HookRegistry's typed user-create hooks (BeforeUserCreate, AfterUserCreate) as database
// hooks, so they apply to every user insert whoever makes it. SetupGoAuth adds them as the first source.
func TypedHooks(hooks plugins.HookRegistry) dbhooks.Hooks {
	if hooks == nil {
		return dbhooks.Hooks{}
	}
	return dbhooks.Hooks{User: dbhooks.ModelHooks[models.User]{Create: dbhooks.CreateHooks[models.User]{
		Before: hooks.TriggerBeforeUserCreate,
		After:  hooks.TriggerAfterUserCreate,
	}}}
}

// fieldValues converts an update map to field names (Go field names of the model's struct are translated)
// with values of each field's logical type. Without a registry the keys are only translated.
func (a *Adapter) fieldValues(model string, data map[string]any) (map[string]any, error) {
	var m *schema.ResolvedModel
	if a.d.Schema != nil {
		m, _ = a.d.Schema.Model(model)
	}
	out := make(map[string]any, len(data))
	for k, v := range data {
		// Step 1: the field name
		if name, ok := adapterrepo.FieldName(model, k); ok {
			k = name
		}
		if m == nil {
			out[k] = v
			continue
		}
		// Step 2: only fields of the model, converted to their type
		f, ok := m.Field(k)
		if !ok {
			continue
		}
		nv, err := schema.Normalize(f.Type, v)
		if err != nil {
			return nil, autherr.ErrValidationError.WithMessage("[body." + k + "] " + err.Error())
		}
		out[k] = nv
	}
	return out, nil
}
