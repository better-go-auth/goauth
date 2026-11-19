// Package adapterrepo implements repo_interfaces.IAuthRepos once, on top of any adapter.Adapter and the
// schema registry (doc 04 §4.3). Go models map to records by registry field name; registry fields without a
// Go field (additionalFields, plugin schema fields) travel in the models' Extra map.
//
// Errors follow the hand-written repositories: lookups that match nothing return autherr.NotFoundErr
// (404, what pluginkit.IsNotFound checks), and unique violations wrap adapter.ErrUniqueViolation.
package adapterrepo

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/dtos"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/schema"
)

// Repos implements repo_interfaces.IAuthRepos on an adapter.
type Repos struct {
	a            adapter.Adapter
	reg          *schema.Registry
	user         *binding
	session      *binding
	account      *binding
	verification *binding
}

var _ repo_interfaces.IAuthRepos = (*Repos)(nil)

// New binds the core Go models to reg and returns the repositories on a. reg must be the registry a was
// built with (adapter.RegistryOf(a) for adapters from adapter.New).
func New(a adapter.Adapter, reg *schema.Registry) (*Repos, error) {
	r := &Repos{a: a, reg: reg}
	// Step 1: bind every core model
	bindings := map[string]**binding{
		schema.ModelUser: &r.user, schema.ModelSession: &r.session,
		schema.ModelAccount: &r.account, schema.ModelVerification: &r.verification,
	}
	for model, dst := range bindings {
		b, err := newBinding(reg, model, bindingSamples[model])
		if err != nil {
			return nil, err
		}
		*dst = b
	}
	return r, nil
}

// MustNew is New for static setups; it panics on error.
func MustNew(a adapter.Adapter, reg *schema.Registry) *Repos {
	r, err := New(a, reg)
	if err != nil {
		panic(err)
	}
	return r
}

// Adapter returns the adapter the repositories use.
func (r *Repos) Adapter() adapter.Adapter { return r.a }

// ─── helpers ─────────────────────────────────────────────────────────────────

func notFound(model string) error { return autherr.NotFoundErr("adapterrepo/" + model + ": not found") }

// isNotFound reports whether err is a repository not-found error.
func isNotFound(err error) bool {
	ae := autherr.AsAuthError(err)
	return ae != nil && ae.StatusCode == http.StatusNotFound
}

// wrap adds context to an adapter error and maps ErrNotFound to the autherr not-found error.
func wrap(model, op string, err error) error {
	if errors.Is(err, adapter.ErrNotFound) {
		return notFound(model)
	}
	return fmt.Errorf("adapterrepo/%s: %s: %w", model, op, err)
}

// stamp fills zero timestamps the way the GORM repositories did (autoCreateTime / autoUpdateTime).
func stamp(b *models.Base) {
	now := schema.DateMillis(time.Now())
	if b.CreatedAt.IsZero() {
		b.CreatedAt = now
	}
	if b.UpdatedAt.IsZero() {
		b.UpdatedAt = now
	}
}

// has reports whether the registry model of b has field.
func has(b *binding, field string) bool { return b.model.Has(field) }

func eq(field string, v any) adapter.Where { return adapter.Where{Field: field, Value: v} }

// liveUser restricts user queries to rows that are not soft-deleted.
func (r *Repos) liveUser(where ...adapter.Where) []adapter.Where {
	if has(r.user, "deletedAt") {
		where = append(where, eq("deletedAt", nil))
	}
	return where
}

// create writes ptr (a model pointer) and fills it with the stored record.
func (r *Repos) create(ctx context.Context, b *binding, ptr any) error {
	rec, err := r.a.Create(ctx, b.model.Name(), b.record(ptr))
	if err != nil {
		return wrap(b.model.Name(), "create", err)
	}
	return b.fill(ptr, rec)
}

// findOne returns the first match decoded into a new T.
func findOne[T any](ctx context.Context, r *Repos, b *binding, where []adapter.Where, sort ...adapter.SortBy) (*T, error) {
	recs, err := r.a.FindMany(ctx, b.model.Name(), adapter.Query{Where: where, Sort: sort, Limit: 1})
	if err != nil {
		return nil, wrap(b.model.Name(), "find", err)
	}
	if len(recs) == 0 {
		return nil, notFound(b.model.Name())
	}
	out := new(T)
	if err := b.fill(out, recs[0]); err != nil {
		return nil, err
	}
	return out, nil
}

// findMany returns every match decoded into Ts (an empty, non-nil slice when nothing matches).
func findMany[T any](ctx context.Context, r *Repos, b *binding, q adapter.Query) ([]T, error) {
	recs, err := r.a.FindMany(ctx, b.model.Name(), q)
	if err != nil {
		return nil, wrap(b.model.Name(), "list", err)
	}
	out := make([]T, len(recs))
	for i, rec := range recs {
		if err := b.fill(&out[i], rec); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// update applies data (Go field names, registry names or columns) to the first match and returns it.
func update[T any](ctx context.Context, r *Repos, b *binding, where []adapter.Where, data map[string]any) (*T, error) {
	rec, err := b.updates(data)
	if err != nil {
		return nil, err
	}
	updated, err := r.a.Update(ctx, b.model.Name(), where, rec)
	if err != nil {
		return nil, wrap(b.model.Name(), "update", err)
	}
	out := new(T)
	if err := b.fill(out, updated); err != nil {
		return nil, err
	}
	return out, nil
}

// deleteWhere removes every match.
func (r *Repos) deleteWhere(ctx context.Context, b *binding, where ...adapter.Where) error {
	if _, err := r.a.DeleteMany(ctx, b.model.Name(), where); err != nil {
		return wrap(b.model.Name(), "delete", err)
	}
	return nil
}

// page returns limit and offset for a 1-based page.
func page(p dtos.PaginationInput, defaultLimit int) (int, int) {
	limit := defaultLimit
	if p.Limit > 0 {
		limit = p.Limit
	}
	offset := 0
	if p.Page > 1 {
		offset = (p.Page - 1) * limit
	}
	return limit, offset
}

// ─── Users ───────────────────────────────────────────────────────────────────

// CreateUser stores a user (email lower-cased, name derived from first/last name when empty).
func (r *Repos) CreateUser(ctx context.Context, user *models.User) (*models.User, error) {
	// Step 1: normalise like the GORM repository (PrepareSave) and require an email
	user.PrepareSave()
	if user.Email == "" {
		return nil, errors.New("adapterrepo/user: email is required")
	}
	stamp(&user.Base)
	// Step 2: insert and refresh the struct from the stored record
	if err := r.create(ctx, r.user, user); err != nil {
		return nil, err
	}
	return user, nil
}

// FindUserByID fetches a live user by id.
func (r *Repos) FindUserByID(ctx context.Context, id string) (*models.User, error) {
	if id == "" {
		return nil, notFound(schema.ModelUser)
	}
	return findOne[models.User](ctx, r, r.user, r.liveUser(eq("id", id)))
}

// FindUserByEmail fetches a live user by email, case-insensitively.
func (r *Repos) FindUserByEmail(ctx context.Context, email string) (*models.User, error) {
	if email == "" {
		return nil, notFound(schema.ModelUser)
	}
	return findOne[models.User](ctx, r, r.user, r.liveUser(adapter.Where{Field: "email", Value: email, Insensitive: true}))
}

// FindUserByPhoneNumber fetches the live user owning phoneNumber (phone-number plugin).
func (r *Repos) FindUserByPhoneNumber(ctx context.Context, phoneNumber string) (*models.User, error) {
	if phoneNumber == "" || !has(r.user, "phoneNumber") {
		return nil, notFound(schema.ModelUser)
	}
	return findOne[models.User](ctx, r, r.user, r.liveUser(eq("phoneNumber", phoneNumber)))
}

// FindUserByUsername fetches the live user owning username, compared exactly (username plugin).
func (r *Repos) FindUserByUsername(ctx context.Context, username string) (*models.User, error) {
	if username == "" || !has(r.user, "username") {
		return nil, notFound(schema.ModelUser)
	}
	return findOne[models.User](ctx, r, r.user, r.liveUser(eq("username", username)))
}

// UpdateUser applies a partial update to a live user and returns it.
func (r *Repos) UpdateUser(ctx context.Context, id string, data map[string]interface{}) (*models.User, error) {
	if id == "" {
		return nil, notFound(schema.ModelUser)
	}
	// Step 1: emails are stored lower-cased
	for k, v := range data {
		if name, ok := r.user.field(k); ok && name == "email" {
			if s, ok := v.(string); ok {
				data[k] = strings.ToLower(strings.TrimSpace(s))
			}
		}
	}
	// Step 2: update the live row
	return update[models.User](ctx, r, r.user, r.liveUser(eq("id", id)), data)
}

// DeleteUser removes the user with their sessions (and the sessions they impersonate) and accounts, in one
// transaction (better-auth's hard delete).
func (r *Repos) DeleteUser(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	return r.a.Transaction(ctx, func(ctx context.Context) error {
		// Step 1: sessions of the user and sessions where the user impersonates someone
		if err := r.deleteWhere(ctx, r.session, eq("userId", id)); err != nil {
			return err
		}
		if has(r.session, "impersonatedBy") {
			if err := r.deleteWhere(ctx, r.session, eq("impersonatedBy", id)); err != nil {
				return err
			}
		}
		// Step 2: linked accounts
		if err := r.deleteWhere(ctx, r.account, eq("userId", id)); err != nil {
			return err
		}
		// Step 3: the user row itself
		return r.deleteWhere(ctx, r.user, eq("id", id))
	})
}

// SoftDeleteUser keeps the row as a tombstone: deletedAt set, email anonymized, phone number and username
// released. A missing (or already deleted) user is not an error.
func (r *Repos) SoftDeleteUser(ctx context.Context, id string) error {
	if id == "" || !has(r.user, "deletedAt") {
		return nil
	}
	// Step 1: the tombstone values
	now := models.TimeNow()
	set := adapter.Record{"deletedAt": now, "email": models.AnonymizeEmail(id, now)}
	// release the unique phone number so it can be registered again
	if has(r.user, "phoneNumber") {
		set["phoneNumber"] = nil
	}
	// release the unique username too (username plugin)
	if has(r.user, "username") {
		set["username"] = nil
	}
	// Step 2: apply them to the live row
	if _, err := r.a.UpdateMany(ctx, schema.ModelUser, r.liveUser(eq("id", id)), set); err != nil {
		return wrap(schema.ModelUser, "soft delete", err)
	}
	return nil
}

// ListUsers returns a page of live users matching filter, plus the total count.
func (r *Repos) ListUsers(ctx context.Context, filter repo_interfaces.UserFilter, pagi dtos.PaginationInput) ([]models.User, int64, error) {
	// Step 1: filters
	where := r.liveUser()
	if filter.Email != nil {
		where = append(where, adapter.Where{Field: "email", Op: adapter.Contains, Value: *filter.Email, Insensitive: true})
	}
	if filter.Role != nil && has(r.user, "role") {
		where = append(where, eq("role", *filter.Role))
	}
	if filter.Banned != nil && has(r.user, "banned") {
		where = append(where, eq("banned", *filter.Banned))
	}
	if filter.SearchField != nil && filter.SearchValue != nil {
		field, err := r.listField(*filter.SearchField)
		if err != nil {
			return nil, 0, fmt.Errorf("adapterrepo/user: invalid search field: %w", err)
		}
		if f, _ := r.user.model.Field(field); f.Type != schema.String {
			return nil, 0, fmt.Errorf("adapterrepo/user: invalid search field %q (not text)", *filter.SearchField)
		}
		where = append(where, adapter.Where{Field: field, Op: adapter.Contains, Value: *filter.SearchValue, Insensitive: true})
	}
	// Step 2: total
	total, err := r.a.Count(ctx, schema.ModelUser, where)
	if err != nil {
		return nil, 0, wrap(schema.ModelUser, "count", err)
	}
	// Step 3: order (createdAt desc by default) and page
	sortBy := "createdAt"
	if pagi.SortBy != "" {
		if sortBy, err = r.listField(pagi.SortBy); err != nil {
			return nil, 0, fmt.Errorf("adapterrepo/user: invalid sort field: %w", err)
		}
	}
	limit, offset := page(pagi, 20)
	users, err := findMany[models.User](ctx, r, r.user, adapter.Query{
		Where: where, Limit: limit, Offset: offset,
		Sort: []adapter.SortBy{{Field: sortBy, Desc: strings.ToLower(pagi.SortDir) != "asc"}},
	})
	if err != nil {
		return nil, 0, err
	}
	return users, total, nil
}

// listField maps an allow-listed sort/search name (repo_interfaces.UserListField) to its registry field.
func (r *Repos) listField(name string) (string, error) {
	goName, ok := repo_interfaces.UserListField(name)
	if !ok {
		return "", fmt.Errorf("%q is not allowed", name)
	}
	field, ok := r.user.field(goName)
	if !ok {
		return "", fmt.Errorf("%q is not a user field", name)
	}
	return field, nil
}

// ─── Sessions ────────────────────────────────────────────────────────────────

// CreateSession stores a session.
func (r *Repos) CreateSession(ctx context.Context, session *models.Session) (*models.Session, error) {
	if session.Token == "" {
		return nil, errors.New("adapterrepo/session: token is required")
	}
	session.EnsureUTC()
	stamp(&session.Base)
	if err := r.create(ctx, r.session, session); err != nil {
		return nil, err
	}
	return session, nil
}

// UpsertSession creates the session, or updates token, device token, organization fields and expiry of
// the session with the same id.
func (r *Repos) UpsertSession(ctx context.Context, session *models.Session) (*models.Session, error) {
	if session.ID == "" {
		return r.CreateSession(ctx, session)
	}
	err := r.a.Transaction(ctx, func(ctx context.Context) error {
		// Step 1: a new id is a create
		if _, err := r.FindSessionByID(ctx, session.ID); err != nil {
			if !isNotFound(err) {
				return err
			}
			_, err = r.CreateSession(ctx, session)
			return err
		}
		// Step 2: an existing id updates the upsert columns
		session.EnsureUTC()
		data := map[string]any{"Token": session.Token, "ExpiresAt": session.ExpiresAt}
		for _, k := range []string{"DeviceToken", "ActiveOrganizationID", "ActiveOrganizationRole", "ActiveOrganizationType"} {
			if _, ok := r.session.byGo[k]; ok {
				data[k] = value(fieldOf(session, k))
			}
		}
		updated, err := update[models.Session](ctx, r, r.session, []adapter.Where{eq("id", session.ID)}, data)
		if err != nil {
			return err
		}
		session.UpdatedAt = updated.UpdatedAt
		return nil
	})
	if err != nil {
		return nil, err
	}
	return session, nil
}

// FindSessionByID fetches a session by id.
func (r *Repos) FindSessionByID(ctx context.Context, id string) (*models.Session, error) {
	if id == "" {
		return nil, notFound(schema.ModelSession)
	}
	return findOne[models.Session](ctx, r, r.session, []adapter.Where{eq("id", id)})
}

// FindSession fetches a session by token.
func (r *Repos) FindSession(ctx context.Context, token string) (*models.Session, error) {
	if token == "" {
		return nil, notFound(schema.ModelSession)
	}
	return findOne[models.Session](ctx, r, r.session, []adapter.Where{eq("token", token)})
}

// UpdateSession applies a partial update and returns the session.
func (r *Repos) UpdateSession(ctx context.Context, id string, data map[string]interface{}) (*models.Session, error) {
	if id == "" {
		return nil, notFound(schema.ModelSession)
	}
	return update[models.Session](ctx, r, r.session, []adapter.Where{eq("id", id)}, data)
}

// DeleteSessionByID deletes the session with id.
func (r *Repos) DeleteSessionByID(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	return r.deleteWhere(ctx, r.session, eq("id", id))
}

// DeleteSession deletes the session with token.
func (r *Repos) DeleteSession(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	return r.deleteWhere(ctx, r.session, eq("token", token))
}

// DeleteUserSessions deletes every session of a user.
func (r *Repos) DeleteUserSessions(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	return r.deleteWhere(ctx, r.session, eq("userId", userID))
}

// ListSessions returns every session of a user, expired ones included.
func (r *Repos) ListSessions(ctx context.Context, userID string) ([]models.Session, error) {
	if userID == "" {
		return []models.Session{}, nil
	}
	return findMany[models.Session](ctx, r, r.session, adapter.Query{Where: []adapter.Where{eq("userId", userID)}})
}

// QuerySessions returns a page of sessions (oldest first) matching filter, plus the total count.
func (r *Repos) QuerySessions(ctx context.Context, filter models.SessionFilter, pagi dtos.PaginationInput) ([]models.Session, int64, error) {
	// Step 1: filters and total
	var where []adapter.Where
	if filter.UserId != "" {
		where = append(where, eq("userId", filter.UserId))
	}
	if filter.ID != "" {
		where = append(where, eq("id", filter.ID))
	}
	total, err := r.a.Count(ctx, schema.ModelSession, where)
	if err != nil {
		return nil, 0, wrap(schema.ModelSession, "count", err)
	}
	// Step 2: the page
	limit, offset := page(pagi, 10)
	sessions, err := findMany[models.Session](ctx, r, r.session, adapter.Query{
		Where: where, Limit: limit, Offset: offset, Sort: []adapter.SortBy{{Field: "createdAt"}},
	})
	if err != nil {
		return nil, 0, err
	}
	return sessions, total, nil
}

// DeleteExpiredSessions deletes sessions whose expiresAt has passed.
func (r *Repos) DeleteExpiredSessions(ctx context.Context) error {
	return r.deleteWhere(ctx, r.session, adapter.Where{Field: "expiresAt", Op: adapter.Lt, Value: time.Now()})
}

// ─── Accounts ────────────────────────────────────────────────────────────────

// CreateAccount stores an account; (providerId, accountId) is unique.
func (r *Repos) CreateAccount(ctx context.Context, account *models.Account) (*models.Account, error) {
	stamp(&account.Base)
	if err := r.create(ctx, r.account, account); err != nil {
		return nil, err
	}
	return account, nil
}

// FindAccountByProviderID fetches the account (providerId, accountId).
func (r *Repos) FindAccountByProviderID(ctx context.Context, providerID models.Providers, accountID string) (*models.Account, error) {
	return findOne[models.Account](ctx, r, r.account, []adapter.Where{eq("providerId", string(providerID)), eq("accountId", accountID)})
}

// FindAccountByUserAndProvider fetches the oldest account of a user for a provider.
func (r *Repos) FindAccountByUserAndProvider(ctx context.Context, userID string, providerID models.Providers) (*models.Account, error) {
	if userID == "" {
		return nil, notFound(schema.ModelAccount)
	}
	return findOne[models.Account](ctx, r, r.account, []adapter.Where{eq("userId", userID), eq("providerId", string(providerID))}, adapter.SortBy{Field: "createdAt"})
}

// UpdateAccount applies a partial update and returns the account.
func (r *Repos) UpdateAccount(ctx context.Context, id string, data map[string]interface{}) (*models.Account, error) {
	if id == "" {
		return nil, notFound(schema.ModelAccount)
	}
	return update[models.Account](ctx, r, r.account, []adapter.Where{eq("id", id)}, data)
}

// FindAccountByID fetches one account by id.
func (r *Repos) FindAccountByID(ctx context.Context, id string) (*models.Account, error) {
	if id == "" {
		return nil, notFound(schema.ModelAccount)
	}
	return findOne[models.Account](ctx, r, r.account, []adapter.Where{eq("id", id)})
}

// DeleteAccounts removes every account of a user.
func (r *Repos) DeleteAccounts(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	return r.deleteWhere(ctx, r.account, eq("userId", userID))
}

// FindAccounts returns every account of a user.
func (r *Repos) FindAccounts(ctx context.Context, userID string) ([]models.Account, error) {
	if userID == "" {
		return []models.Account{}, nil
	}
	return findMany[models.Account](ctx, r, r.account, adapter.Query{Where: []adapter.Where{eq("userId", userID)}})
}

// DeleteAccountByUserAndProvider removes a user's accounts of one provider (/unlink-account).
func (r *Repos) DeleteAccountByUserAndProvider(ctx context.Context, userID, providerID string) error {
	if userID == "" {
		return nil
	}
	return r.deleteWhere(ctx, r.account, eq("userId", userID), eq("providerId", providerID))
}

// DeleteAccount removes one account by id.
func (r *Repos) DeleteAccount(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	return r.deleteWhere(ctx, r.account, eq("id", id))
}

// ─── Verifications ───────────────────────────────────────────────────────────

// UpsertVerificationValue replaces every verification with the same identifier by v.
func (r *Repos) UpsertVerificationValue(ctx context.Context, v *models.Verification) (*models.Verification, error) {
	v.EnsureUTC()
	stamp(&v.Base)
	err := r.a.Transaction(ctx, func(ctx context.Context) error {
		// Step 1: identifier is not unique in better-auth's schema, so delete then insert
		if err := r.deleteWhere(ctx, r.verification, eq("identifier", v.Identifier)); err != nil {
			return err
		}
		// Step 2: the new row
		return r.create(ctx, r.verification, v)
	})
	if err != nil {
		return nil, err
	}
	return v, nil
}

// newestVerification returns the newest verification for identifier.
func (r *Repos) newestVerification(ctx context.Context, identifier string) (*models.Verification, error) {
	if identifier == "" {
		return nil, notFound(schema.ModelVerification)
	}
	return findOne[models.Verification](ctx, r, r.verification, []adapter.Where{eq("identifier", identifier)}, adapter.SortBy{Field: "createdAt", Desc: true})
}

// FindVerificationValue fetches the newest verification for identifier.
func (r *Repos) FindVerificationValue(ctx context.Context, identifier string) (*models.Verification, error) {
	return r.newestVerification(ctx, identifier)
}

// DeleteVerificationByIdentifier deletes every verification with identifier.
func (r *Repos) DeleteVerificationByIdentifier(ctx context.Context, identifier string) error {
	if identifier == "" {
		return nil
	}
	return r.deleteWhere(ctx, r.verification, eq("identifier", identifier))
}

// ConsumeVerificationValue deletes and returns the newest live verification for identifier; only the
// caller whose delete removes the row gets it, and expired rows are deleted but reported as not found.
func (r *Repos) ConsumeVerificationValue(ctx context.Context, identifier string) (*models.Verification, error) {
	// Step 1: the newest row
	v, err := r.newestVerification(ctx, identifier)
	if err != nil {
		return nil, err
	}
	// Step 2: deleting by id decides the race
	n, err := r.a.DeleteMany(ctx, schema.ModelVerification, []adapter.Where{eq("id", v.ID)})
	if err != nil {
		return nil, wrap(schema.ModelVerification, "consume", err)
	}
	if n == 0 || v.IsExpired() {
		return nil, notFound(schema.ModelVerification)
	}
	return v, nil
}

// DeleteVerificationsByValue deletes the verifications holding value whose identifier starts with
// identifierPrefix. Empty arguments delete nothing.
func (r *Repos) DeleteVerificationsByValue(ctx context.Context, identifierPrefix, value string) error {
	if identifierPrefix == "" || value == "" {
		return nil
	}
	return r.deleteWhere(ctx, r.verification, eq("value", value), adapter.Where{Field: "identifier", Op: adapter.StartsWith, Value: identifierPrefix})
}

// DeleteExpiredVerifications removes every expired verification.
func (r *Repos) DeleteExpiredVerifications(ctx context.Context) error {
	return r.deleteWhere(ctx, r.verification, adapter.Where{Field: "expiresAt", Op: adapter.Lt, Value: time.Now()})
}

// UpdateVerificationValue replaces the value of verification id only while it still holds oldValue
// (compare-and-swap: UPDATE ... WHERE id = ? AND value = ?).
func (r *Repos) UpdateVerificationValue(ctx context.Context, id, oldValue, newValue string) (bool, error) {
	if id == "" {
		return false, nil
	}
	n, err := r.a.UpdateMany(ctx, schema.ModelVerification, []adapter.Where{eq("id", id), eq("value", oldValue)}, adapter.Record{"value": newValue})
	if err != nil {
		return false, wrap(schema.ModelVerification, "update value", err)
	}
	return n == 1, nil
}

// DeleteVerificationIfValue deletes verification id only while it still holds value.
func (r *Repos) DeleteVerificationIfValue(ctx context.Context, id, value string) (bool, error) {
	if id == "" {
		return false, nil
	}
	n, err := r.a.DeleteMany(ctx, schema.ModelVerification, []adapter.Where{eq("id", id), eq("value", value)})
	if err != nil {
		return false, wrap(schema.ModelVerification, "delete if value", err)
	}
	return n == 1, nil
}
