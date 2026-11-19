// Package hookedrepo runs better-auth's database hooks (package dbhooks) around every write of goauth's
// repositories: whichever endpoint or plugin creates, updates or deletes a user, session, account or
// verification through repo_interfaces.IAuthRepos, the hooks see it, like better-auth's internalAdapter
// (createWithHooks / updateWithHooks / deleteWithHooks).
//
// Update hooks see the change set keyed by better-auth's field names ("emailVerified"), whatever spelling
// the caller used (Go field names such as "EmailVerified" are translated, and translated back for the
// repository).
package hookedrepo

import (
	"context"
	"errors"

	"github.com/better-go-auth/goauth/src/app/repository/adapterrepo"
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/dbhooks"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/schema"
)

// HookError wraps an error returned by a database Before hook, so callers can tell a hook's rejection
// (returned to the client as is, like a thrown APIError) from a storage failure.
type HookError struct{ Err error }

func (e *HookError) Error() string { return e.Err.Error() }
func (e *HookError) Unwrap() error { return e.Err }

// IsHookError reports whether err came from a database Before hook (ErrCancel included).
func IsHookError(err error) bool {
	var he *HookError
	return errors.As(err, &he)
}

// accountFinder is implemented by repositories that can read one account by id (adapterrepo, gormauth,
// memory); delete hooks of DeleteAccount need the record.
type accountFinder interface {
	FindAccountByID(ctx context.Context, id string) (*models.Account, error)
}

// Repos wraps IAuthRepos with database hooks.
type Repos struct {
	repo_interfaces.IAuthRepos
	hooks *dbhooks.Set
}

// Wrap returns repos with hooks applied to every write. A nil set returns repos unchanged.
func Wrap(repos repo_interfaces.IAuthRepos, hooks *dbhooks.Set) repo_interfaces.IAuthRepos {
	if repos == nil || hooks == nil {
		return repos
	}
	return &Repos{IAuthRepos: repos, hooks: hooks}
}

// Unwrap returns the wrapped repositories.
func (r *Repos) Unwrap() repo_interfaces.IAuthRepos { return r.IAuthRepos }

// before wraps a Before hook error.
func before(err error) error {
	if err == nil {
		return nil
	}
	return &HookError{Err: err}
}

// bookkeeping are goauth's own bookkeeping columns (not in better-auth): updates that only touch them (the
// last sign-in time and IP written on every sign-in, a session's last use) don't run update hooks, since
// better-auth makes no such write.
var bookkeeping = map[string]map[string]bool{
	schema.ModelUser:    {"lastLoginAt": true, "lastLoginIP": true, "lastSeen": true},
	schema.ModelSession: {"lastUsedAt": true},
}

// onlyBookkeeping reports whether every key of changes is a bookkeeping column of model.
func onlyBookkeeping(model string, changes map[string]any) bool {
	for k := range changes {
		if !bookkeeping[model][k] {
			return false
		}
	}
	return len(changes) > 0
}

// toFieldNames converts an update map to better-auth's field names (Go field names of the model's struct
// are translated; registry names and columns pass through).
func toFieldNames(model string, data map[string]any) map[string]any {
	out := make(map[string]any, len(data))
	for k, v := range data {
		if name, ok := adapterrepo.FieldName(model, k); ok {
			k = name
		}
		out[k] = v
	}
	return out
}

// toRepoKeys converts a field-name change set back to the keys every repository understands: Go field names
// for the struct's fields, field names for runtime (Extra) fields.
func toRepoKeys(model string, data map[string]any) map[string]any {
	out := make(map[string]any, len(data))
	for k, v := range data {
		if goName, ok := adapterrepo.GoFieldName(model, k); ok {
			k = goName
		}
		out[k] = v
	}
	return out
}

// ─── Users ───────────────────────────────────────────────────────────────────

// CreateUser runs user create hooks around the insert. A cancelled create returns dbhooks.ErrCancel
// (wrapped in *HookError).
func (r *Repos) CreateUser(ctx context.Context, user *models.User) (*models.User, error) {
	// Step 1: before hooks may change or veto the user
	if err := dbhooks.RunCreateBefore(ctx, r.hooks, dbhooks.User, user); err != nil {
		return nil, before(err)
	}
	// Step 2: insert
	created, err := r.IAuthRepos.CreateUser(ctx, user)
	if err != nil {
		return nil, err
	}
	// Step 3: after hooks (after the commit when inside a transaction)
	if err := dbhooks.RunCreateAfter(ctx, r.hooks, dbhooks.User, created); err != nil {
		return nil, err
	}
	return created, nil
}

// UpdateUser runs user update hooks around the update. A cancelled update writes nothing and returns the
// stored user unchanged (better-auth's updateWithHooks returns null and callers carry on).
func (r *Repos) UpdateUser(ctx context.Context, id string, data map[string]interface{}) (*models.User, error) {
	// Step 1: before hooks see (and may change) the change set by field name
	changes := toFieldNames(schema.ModelUser, data)
	if onlyBookkeeping(schema.ModelUser, changes) {
		return r.IAuthRepos.UpdateUser(ctx, id, data)
	}
	if err := dbhooks.RunUpdateBefore(dbhooks.WithTarget(ctx, id), r.hooks, dbhooks.User, changes); err != nil {
		if dbhooks.IsCancel(err) {
			return r.IAuthRepos.FindUserByID(ctx, id)
		}
		return nil, before(err)
	}
	// Step 2: update
	updated, err := r.IAuthRepos.UpdateUser(ctx, id, toRepoKeys(schema.ModelUser, changes))
	if err != nil {
		return nil, err
	}
	// Step 3: after hooks
	if err := dbhooks.RunUpdateAfter(ctx, r.hooks, dbhooks.User, updated); err != nil {
		return nil, err
	}
	return updated, nil
}

// deleteUser runs user delete hooks around del (hard or soft delete).
func (r *Repos) deleteUser(ctx context.Context, id string, del func(ctx context.Context, id string) error) error {
	// Step 1: the record the hooks see (no hooks, no read)
	if !dbhooks.Has(r.hooks, dbhooks.User) {
		return del(ctx, id)
	}
	user, _ := r.IAuthRepos.FindUserByID(ctx, id)
	if user != nil {
		if err := dbhooks.RunDeleteBefore(ctx, r.hooks, dbhooks.User, user); err != nil {
			if dbhooks.IsCancel(err) {
				return nil
			}
			return before(err)
		}
	}
	// Step 2: delete
	if err := del(ctx, id); err != nil {
		return err
	}
	// Step 3: after hooks
	if user != nil {
		return dbhooks.RunDeleteAfter(ctx, r.hooks, dbhooks.User, user)
	}
	return nil
}

// DeleteUser runs user delete hooks around the hard delete.
func (r *Repos) DeleteUser(ctx context.Context, id string) error {
	return r.deleteUser(ctx, id, r.IAuthRepos.DeleteUser)
}

// SoftDeleteUser runs user delete hooks around the soft delete (User.GoAuth.SoftDelete).
func (r *Repos) SoftDeleteUser(ctx context.Context, id string) error {
	return r.deleteUser(ctx, id, r.IAuthRepos.SoftDeleteUser)
}

// ─── Sessions ────────────────────────────────────────────────────────────────

// CreateSession runs session create hooks around the insert.
func (r *Repos) CreateSession(ctx context.Context, session *models.Session) (*models.Session, error) {
	if err := dbhooks.RunCreateBefore(ctx, r.hooks, dbhooks.Session, session); err != nil {
		return nil, before(err)
	}
	created, err := r.IAuthRepos.CreateSession(ctx, session)
	if err != nil {
		return nil, err
	}
	if err := dbhooks.RunCreateAfter(ctx, r.hooks, dbhooks.Session, created); err != nil {
		return nil, err
	}
	return created, nil
}

// UpdateSession runs session update hooks around the update; a cancelled update returns the stored session.
func (r *Repos) UpdateSession(ctx context.Context, id string, data map[string]interface{}) (*models.Session, error) {
	changes := toFieldNames(schema.ModelSession, data)
	if onlyBookkeeping(schema.ModelSession, changes) {
		return r.IAuthRepos.UpdateSession(ctx, id, data)
	}
	if err := dbhooks.RunUpdateBefore(dbhooks.WithTarget(ctx, id), r.hooks, dbhooks.Session, changes); err != nil {
		if dbhooks.IsCancel(err) {
			return r.IAuthRepos.FindSessionByID(ctx, id)
		}
		return nil, before(err)
	}
	updated, err := r.IAuthRepos.UpdateSession(ctx, id, toRepoKeys(schema.ModelSession, changes))
	if err != nil {
		return nil, err
	}
	if err := dbhooks.RunUpdateAfter(ctx, r.hooks, dbhooks.Session, updated); err != nil {
		return nil, err
	}
	return updated, nil
}

// deleteSessions runs session delete hooks for each of list around del.
func (r *Repos) deleteSessions(ctx context.Context, list []models.Session, del func() error) error {
	// Step 1: before hooks for every session (a cancel stops the whole delete, like deleteManyWithHooks)
	for i := range list {
		if err := dbhooks.RunDeleteBefore(ctx, r.hooks, dbhooks.Session, &list[i]); err != nil {
			if dbhooks.IsCancel(err) {
				return nil
			}
			return before(err)
		}
	}
	// Step 2: delete
	if err := del(); err != nil {
		return err
	}
	// Step 3: after hooks
	for i := range list {
		if err := dbhooks.RunDeleteAfter(ctx, r.hooks, dbhooks.Session, &list[i]); err != nil {
			return err
		}
	}
	return nil
}

// one returns a one-element list, or nil for a nil record.
func one[T any](v *T) []T {
	if v == nil {
		return nil
	}
	return []T{*v}
}

// DeleteSession runs session delete hooks around the delete by token.
func (r *Repos) DeleteSession(ctx context.Context, token string) error {
	if !dbhooks.Has(r.hooks, dbhooks.Session) {
		return r.IAuthRepos.DeleteSession(ctx, token)
	}
	s, _ := r.IAuthRepos.FindSession(ctx, token)
	return r.deleteSessions(ctx, one(s), func() error { return r.IAuthRepos.DeleteSession(ctx, token) })
}

// DeleteSessionByID runs session delete hooks around the delete by id.
func (r *Repos) DeleteSessionByID(ctx context.Context, id string) error {
	if !dbhooks.Has(r.hooks, dbhooks.Session) {
		return r.IAuthRepos.DeleteSessionByID(ctx, id)
	}
	s, _ := r.IAuthRepos.FindSessionByID(ctx, id)
	return r.deleteSessions(ctx, one(s), func() error { return r.IAuthRepos.DeleteSessionByID(ctx, id) })
}

// DeleteUserSessions runs session delete hooks for every session of the user around the delete.
func (r *Repos) DeleteUserSessions(ctx context.Context, userID string) error {
	if !dbhooks.Has(r.hooks, dbhooks.Session) {
		return r.IAuthRepos.DeleteUserSessions(ctx, userID)
	}
	list, _ := r.IAuthRepos.ListSessions(ctx, userID)
	return r.deleteSessions(ctx, list, func() error { return r.IAuthRepos.DeleteUserSessions(ctx, userID) })
}

// ─── Accounts ────────────────────────────────────────────────────────────────

// CreateAccount runs account create hooks around the insert (better-auth's linkAccount / createAccount).
func (r *Repos) CreateAccount(ctx context.Context, account *models.Account) (*models.Account, error) {
	if err := dbhooks.RunCreateBefore(ctx, r.hooks, dbhooks.Account, account); err != nil {
		return nil, before(err)
	}
	created, err := r.IAuthRepos.CreateAccount(ctx, account)
	if err != nil {
		return nil, err
	}
	if err := dbhooks.RunCreateAfter(ctx, r.hooks, dbhooks.Account, created); err != nil {
		return nil, err
	}
	return created, nil
}

// UpdateAccount runs account update hooks around the update; a cancelled update returns the stored account.
func (r *Repos) UpdateAccount(ctx context.Context, id string, data map[string]interface{}) (*models.Account, error) {
	changes := toFieldNames(schema.ModelAccount, data)
	if err := dbhooks.RunUpdateBefore(dbhooks.WithTarget(ctx, id), r.hooks, dbhooks.Account, changes); err != nil {
		if dbhooks.IsCancel(err) {
			return r.findAccount(ctx, id)
		}
		return nil, before(err)
	}
	updated, err := r.IAuthRepos.UpdateAccount(ctx, id, toRepoKeys(schema.ModelAccount, changes))
	if err != nil {
		return nil, err
	}
	if err := dbhooks.RunUpdateAfter(ctx, r.hooks, dbhooks.Account, updated); err != nil {
		return nil, err
	}
	return updated, nil
}

// findAccount reads one account by id when the repositories can.
func (r *Repos) findAccount(ctx context.Context, id string) (*models.Account, error) {
	if f, ok := r.IAuthRepos.(accountFinder); ok {
		return f.FindAccountByID(ctx, id)
	}
	return nil, nil
}

// deleteAccounts runs account delete hooks for each of list around del.
func (r *Repos) deleteAccounts(ctx context.Context, list []models.Account, del func() error) error {
	for i := range list {
		if err := dbhooks.RunDeleteBefore(ctx, r.hooks, dbhooks.Account, &list[i]); err != nil {
			if dbhooks.IsCancel(err) {
				return nil
			}
			return before(err)
		}
	}
	if err := del(); err != nil {
		return err
	}
	for i := range list {
		if err := dbhooks.RunDeleteAfter(ctx, r.hooks, dbhooks.Account, &list[i]); err != nil {
			return err
		}
	}
	return nil
}

// DeleteAccounts runs account delete hooks for every account of the user around the delete.
func (r *Repos) DeleteAccounts(ctx context.Context, userID string) error {
	if !dbhooks.Has(r.hooks, dbhooks.Account) {
		return r.IAuthRepos.DeleteAccounts(ctx, userID)
	}
	list, _ := r.IAuthRepos.FindAccounts(ctx, userID)
	return r.deleteAccounts(ctx, list, func() error { return r.IAuthRepos.DeleteAccounts(ctx, userID) })
}

// DeleteAccountByUserAndProvider runs account delete hooks for the user's accounts of the provider.
func (r *Repos) DeleteAccountByUserAndProvider(ctx context.Context, userID, providerID string) error {
	if !dbhooks.Has(r.hooks, dbhooks.Account) {
		return r.IAuthRepos.DeleteAccountByUserAndProvider(ctx, userID, providerID)
	}
	all, _ := r.IAuthRepos.FindAccounts(ctx, userID)
	var list []models.Account
	for _, a := range all {
		if string(a.ProviderID) == providerID {
			list = append(list, a)
		}
	}
	return r.deleteAccounts(ctx, list, func() error { return r.IAuthRepos.DeleteAccountByUserAndProvider(ctx, userID, providerID) })
}

// DeleteAccount runs account delete hooks around the delete by id.
func (r *Repos) DeleteAccount(ctx context.Context, id string) error {
	if !dbhooks.Has(r.hooks, dbhooks.Account) {
		return r.IAuthRepos.DeleteAccount(ctx, id)
	}
	a, _ := r.findAccount(ctx, id)
	return r.deleteAccounts(ctx, one(a), func() error { return r.IAuthRepos.DeleteAccount(ctx, id) })
}

// FindAccountByID reads one account by id (nil, nil when the repositories can't).
func (r *Repos) FindAccountByID(ctx context.Context, id string) (*models.Account, error) {
	return r.findAccount(ctx, id)
}

// ─── Verifications ───────────────────────────────────────────────────────────

// UpsertVerificationValue runs verification create hooks around the insert (better-auth's
// createVerificationValue).
func (r *Repos) UpsertVerificationValue(ctx context.Context, v *models.Verification) (*models.Verification, error) {
	if err := dbhooks.RunCreateBefore(ctx, r.hooks, dbhooks.Verification, v); err != nil {
		return nil, before(err)
	}
	created, err := r.IAuthRepos.UpsertVerificationValue(ctx, v)
	if err != nil {
		return nil, err
	}
	if err := dbhooks.RunCreateAfter(ctx, r.hooks, dbhooks.Verification, created); err != nil {
		return nil, err
	}
	return created, nil
}

// DeleteVerificationByIdentifier runs verification delete hooks (on the newest row) around the delete.
func (r *Repos) DeleteVerificationByIdentifier(ctx context.Context, identifier string) error {
	if !dbhooks.Has(r.hooks, dbhooks.Verification) {
		return r.IAuthRepos.DeleteVerificationByIdentifier(ctx, identifier)
	}
	v, _ := r.IAuthRepos.FindVerificationValue(ctx, identifier)
	if v != nil {
		if err := dbhooks.RunDeleteBefore(ctx, r.hooks, dbhooks.Verification, v); err != nil {
			if dbhooks.IsCancel(err) {
				return nil
			}
			return before(err)
		}
	}
	if err := r.IAuthRepos.DeleteVerificationByIdentifier(ctx, identifier); err != nil {
		return err
	}
	if v != nil {
		return dbhooks.RunDeleteAfter(ctx, r.hooks, dbhooks.Verification, v)
	}
	return nil
}

// ConsumeVerificationValue runs verification delete hooks around the atomic consume (better-auth's
// consumeOneWithHooks): before hooks see the newest row, after hooks the consumed one; a cancel consumes
// nothing and reports not found.
func (r *Repos) ConsumeVerificationValue(ctx context.Context, identifier string) (*models.Verification, error) {
	// Step 1: before hooks on a snapshot of the newest row
	if dbhooks.Has(r.hooks, dbhooks.Verification) {
		if snap, _ := r.IAuthRepos.FindVerificationValue(ctx, identifier); snap != nil {
			if err := dbhooks.RunDeleteBefore(ctx, r.hooks, dbhooks.Verification, snap); err != nil {
				if dbhooks.IsCancel(err) {
					return nil, autherr.NotFoundErr("verification: consume cancelled by a database hook")
				}
				return nil, before(err)
			}
		}
	}
	// Step 2: the atomic consume is the race gate
	v, err := r.IAuthRepos.ConsumeVerificationValue(ctx, identifier)
	if err != nil || v == nil {
		return v, err
	}
	// Step 3: after hooks only for the winner
	if err := dbhooks.RunDeleteAfter(ctx, r.hooks, dbhooks.Verification, v); err != nil {
		return nil, err
	}
	return v, nil
}

// UpdateVerificationValue runs verification update hooks ({"value": newValue}) around the compare-and-swap.
// A cancel leaves the row unchanged and reports false.
func (r *Repos) UpdateVerificationValue(ctx context.Context, id, oldValue, newValue string) (bool, error) {
	// Step 1: before hooks may change the new value or cancel
	changes := map[string]any{"value": newValue}
	if err := dbhooks.RunUpdateBefore(dbhooks.WithTarget(ctx, id), r.hooks, dbhooks.Verification, changes); err != nil {
		if dbhooks.IsCancel(err) {
			return false, nil
		}
		return false, before(err)
	}
	if s, ok := changes["value"].(string); ok {
		newValue = s
	}
	// Step 2: the compare-and-swap
	ok, err := r.IAuthRepos.UpdateVerificationValue(ctx, id, oldValue, newValue)
	if err != nil || !ok {
		return ok, err
	}
	// Step 3: after hooks with what was written
	return true, dbhooks.RunUpdateAfter(ctx, r.hooks, dbhooks.Verification, &models.Verification{Base: models.Base{ID: id}, Value: newValue})
}

// DeleteVerificationIfValue runs verification delete hooks around the conditional delete.
func (r *Repos) DeleteVerificationIfValue(ctx context.Context, id, value string) (bool, error) {
	v := &models.Verification{Base: models.Base{ID: id}, Value: value}
	if err := dbhooks.RunDeleteBefore(ctx, r.hooks, dbhooks.Verification, v); err != nil {
		if dbhooks.IsCancel(err) {
			return false, nil
		}
		return false, before(err)
	}
	ok, err := r.IAuthRepos.DeleteVerificationIfValue(ctx, id, value)
	if err != nil || !ok {
		return ok, err
	}
	return true, dbhooks.RunDeleteAfter(ctx, r.hooks, dbhooks.Verification, v)
}
