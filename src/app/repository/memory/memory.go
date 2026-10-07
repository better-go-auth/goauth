// Package memory is an in-memory implementation of the auth repositories, for tests and examples.
package memory

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/common/dtos"
	loc_errors "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/models"
)

// Repos implements repo_interfaces.IAuthRepos in memory. It is safe for concurrent use.
type Repos struct {
	mu            sync.RWMutex
	users         map[string]*models.User
	sessions      map[string]*models.Session
	accounts      map[string]*models.Account
	verifications map[string]*models.Verification
}

var _ repo_interfaces.IAuthRepos = (*Repos)(nil)

// New returns empty in-memory repositories.
func New() *Repos {
	return &Repos{
		users:         map[string]*models.User{},
		sessions:      map[string]*models.Session{},
		accounts:      map[string]*models.Account{},
		verifications: map[string]*models.Verification{},
	}
}

func notFound(what string) error { return loc_errors.NotFoundErr("memory: " + what + " not found") }

func stamp(b *models.Base) {
	now := time.Now().UTC()
	if b.ID == "" {
		b.ID = models.NewID()
	}
	if b.CreatedAt.IsZero() {
		b.CreatedAt = now
	}
	b.UpdatedAt = now
}

// ─── Users ───────────────────────────────────────────────────────────────────

func (r *Repos) CreateUser(_ context.Context, user *models.User) (*models.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if user.Name == "" {
		user.Name = user.DisplayNameOrFull()
	}
	user.Email = strings.ToLower(strings.TrimSpace(user.Email))
	if user.Email == "" {
		return nil, errors.New("memory: user email is required")
	}
	for _, u := range r.users {
		if u.Email == user.Email {
			return nil, errors.New("memory: user email already exists")
		}
	}
	stamp(&user.Base)
	c := *user
	r.users[c.ID] = &c
	return user, nil
}

func (r *Repos) liveUser(id string) (*models.User, bool) {
	u, ok := r.users[id]
	if !ok || u.DeletedAt.Valid {
		return nil, false
	}
	return u, true
}

func (r *Repos) FindUserByID(_ context.Context, id string) (*models.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if u, ok := r.liveUser(id); ok {
		c := *u
		return &c, nil
	}
	return nil, notFound("user")
}

func (r *Repos) FindUserByEmail(_ context.Context, email string) (*models.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, u := range r.users {
		if !u.DeletedAt.Valid && email != "" && strings.EqualFold(u.Email, email) {
			c := *u
			return &c, nil
		}
	}
	return nil, notFound("user")
}

func (r *Repos) UpdateUser(_ context.Context, id string, data map[string]interface{}) (*models.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.liveUser(id)
	if !ok {
		return nil, notFound("user")
	}
	next := *u
	if err := applyUpdates(&next, data); err != nil {
		return nil, err
	}
	next.Email = strings.ToLower(strings.TrimSpace(next.Email))
	next.UpdatedAt = time.Now().UTC()
	r.users[id] = &next
	c := next
	return &c, nil
}

func (r *Repos) DeleteUser(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.liveUser(id)
	if !ok {
		return nil
	}
	now := time.Now().UTC()
	u.DeletedAt.Time, u.DeletedAt.Valid = now, true
	u.Email = models.AnonymizeEmail(id, now)
	return nil
}

func (r *Repos) ListUsers(_ context.Context, filter repo_interfaces.UserFilter, pagi dtos.PaginationInput) ([]models.User, int64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var searchField string
	if filter.SearchField != nil && filter.SearchValue != nil {
		f, ok := repo_interfaces.UserListField(*filter.SearchField)
		if !ok {
			return nil, 0, errors.New("memory: invalid search field")
		}
		searchField = f
	}
	sortBy := "CreatedAt"
	if pagi.SortBy != "" {
		f, ok := repo_interfaces.UserListField(pagi.SortBy)
		if !ok {
			return nil, 0, errors.New("memory: invalid sort field")
		}
		sortBy = f
	}

	var out []models.User
	for _, u := range r.users {
		if u.DeletedAt.Valid {
			continue
		}
		if filter.Email != nil && !containsFold(u.Email, *filter.Email) {
			continue
		}
		if filter.Role != nil && string(u.Role) != *filter.Role {
			continue
		}
		if filter.Banned != nil && u.Banned != *filter.Banned {
			continue
		}
		if searchField != "" && !containsFold(fmt.Sprint(fieldValue(u, searchField)), *filter.SearchValue) {
			continue
		}
		out = append(out, *u)
	}
	desc := strings.ToLower(pagi.SortDir) != "asc"
	sort.SliceStable(out, func(i, j int) bool {
		less := lessValue(fieldValue(&out[i], sortBy), fieldValue(&out[j], sortBy))
		if desc {
			return lessValue(fieldValue(&out[j], sortBy), fieldValue(&out[i], sortBy))
		}
		return less
	})
	limit := 20
	if pagi.Limit > 0 {
		limit = pagi.Limit
	}
	return page(out, pagi.Page, limit), int64(len(out)), nil
}

// ─── Sessions ────────────────────────────────────────────────────────────────

func (r *Repos) CreateSession(_ context.Context, session *models.Session) (*models.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkToken(session); err != nil {
		return nil, err
	}
	stamp(&session.Base)
	c := *session
	r.sessions[c.ID] = &c
	return session, nil
}

func (r *Repos) checkToken(session *models.Session) error {
	if session.Token == "" {
		return errors.New("memory: session token is required")
	}
	for id, s := range r.sessions {
		if s.Token == session.Token && id != session.ID {
			return errors.New("memory: session token already exists")
		}
	}
	return nil
}

func (r *Repos) UpsertSession(ctx context.Context, session *models.Session) (*models.Session, error) {
	r.mu.Lock()
	existing, ok := r.sessions[session.ID]
	if !ok || session.ID == "" {
		r.mu.Unlock()
		return r.CreateSession(ctx, session)
	}
	defer r.mu.Unlock()
	if err := r.checkToken(session); err != nil {
		return nil, err
	}
	existing.Token = session.Token
	existing.DeviceToken = session.DeviceToken
	existing.ActiveOrganizationID = session.ActiveOrganizationID
	existing.ActiveOrganizationRole = session.ActiveOrganizationRole
	existing.ExpiresAt = session.ExpiresAt
	existing.UpdatedAt = time.Now().UTC()
	return session, nil
}

func (r *Repos) FindSessionByID(_ context.Context, id string) (*models.Session, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if s, ok := r.sessions[id]; ok {
		c := *s
		return &c, nil
	}
	return nil, notFound("session")
}

func (r *Repos) FindSession(_ context.Context, token string) (*models.Session, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.sessions {
		if token != "" && s.Token == token {
			c := *s
			return &c, nil
		}
	}
	return nil, notFound("session")
}

func (r *Repos) UpdateSession(_ context.Context, id string, data map[string]interface{}) (*models.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	if !ok {
		return nil, notFound("session")
	}
	next := *s
	if err := applyUpdates(&next, data); err != nil {
		return nil, err
	}
	if _, set := data["UpdatedAt"]; !set {
		next.UpdatedAt = time.Now().UTC()
	}
	r.sessions[id] = &next
	c := next
	return &c, nil
}

func (r *Repos) DeleteSessionByID(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, id)
	return nil
}

func (r *Repos) DeleteSession(_ context.Context, token string) error {
	return r.deleteSessionsWhere(func(s *models.Session) bool { return token != "" && s.Token == token })
}

func (r *Repos) DeleteUserSessions(_ context.Context, userID string) error {
	return r.deleteSessionsWhere(func(s *models.Session) bool { return userID != "" && s.UserID == userID })
}

func (r *Repos) DeleteExpiredSessions(_ context.Context) error {
	now := time.Now().UTC()
	return r.deleteSessionsWhere(func(s *models.Session) bool { return s.ExpiresAt.Before(now) })
}

func (r *Repos) deleteSessionsWhere(match func(*models.Session) bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, s := range r.sessions {
		if match(s) {
			delete(r.sessions, id)
		}
	}
	return nil
}

func (r *Repos) ListSessions(_ context.Context, userID string) ([]models.Session, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []models.Session{}
	for _, s := range r.sessions {
		if userID != "" && s.UserID == userID {
			out = append(out, *s)
		}
	}
	return out, nil
}

func (r *Repos) QuerySessions(_ context.Context, filter models.SessionFilter, pagi dtos.PaginationInput) ([]models.Session, int64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []models.Session
	for _, s := range r.sessions {
		if filter.UserId != "" && s.UserID != filter.UserId {
			continue
		}
		if filter.ID != "" && s.ID != filter.ID {
			continue
		}
		out = append(out, *s)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	limit := 10
	if pagi.Limit > 0 {
		limit = pagi.Limit
	}
	return page(out, pagi.Page, limit), int64(len(out)), nil
}

// ─── Accounts ────────────────────────────────────────────────────────────────

func (r *Repos) CreateAccount(_ context.Context, account *models.Account) (*models.Account, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	stamp(&account.Base)
	c := *account
	r.accounts[c.ID] = &c
	return account, nil
}

func (r *Repos) findAccount(match func(*models.Account) bool) (*models.Account, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, a := range r.accounts {
		if match(a) {
			c := *a
			return &c, nil
		}
	}
	return nil, notFound("account")
}

func (r *Repos) FindAccountByProviderID(_ context.Context, providerID models.Providers, accountID string) (*models.Account, error) {
	return r.findAccount(func(a *models.Account) bool { return a.ProviderID == providerID && a.AccountID == accountID })
}

func (r *Repos) FindAccountByUserAndProvider(_ context.Context, userID string, providerID models.Providers) (*models.Account, error) {
	return r.findAccount(func(a *models.Account) bool { return a.UserID == userID && a.ProviderID == providerID })
}

func (r *Repos) UpdateAccount(_ context.Context, id string, data map[string]interface{}) (*models.Account, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.accounts[id]
	if !ok {
		return nil, notFound("account")
	}
	next := *a
	if err := applyUpdates(&next, data); err != nil {
		return nil, err
	}
	next.UpdatedAt = time.Now().UTC()
	r.accounts[id] = &next
	c := next
	return &c, nil
}

func (r *Repos) DeleteAccounts(_ context.Context, userID string) error {
	return r.deleteAccountsWhere(func(a *models.Account) bool { return userID != "" && a.UserID == userID })
}

func (r *Repos) DeleteAccountByUserAndProvider(_ context.Context, userID, providerID string) error {
	return r.deleteAccountsWhere(func(a *models.Account) bool {
		return userID != "" && a.UserID == userID && string(a.ProviderID) == providerID
	})
}

func (r *Repos) DeleteAccount(_ context.Context, id string) error {
	return r.deleteAccountsWhere(func(a *models.Account) bool { return id != "" && a.ID == id })
}

func (r *Repos) deleteAccountsWhere(match func(*models.Account) bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, a := range r.accounts {
		if match(a) {
			delete(r.accounts, id)
		}
	}
	return nil
}

func (r *Repos) FindAccounts(_ context.Context, userID string) ([]models.Account, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []models.Account{}
	for _, a := range r.accounts {
		if userID != "" && a.UserID == userID {
			out = append(out, *a)
		}
	}
	return out, nil
}

// ─── Verifications ───────────────────────────────────────────────────────────

func (r *Repos) UpsertVerificationValue(_ context.Context, v *models.Verification) (*models.Verification, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, existing := range r.verifications {
		if existing.Identifier == v.Identifier {
			delete(r.verifications, id)
		}
	}
	stamp(&v.Base)
	c := *v
	r.verifications[c.ID] = &c
	return v, nil
}

func (r *Repos) FindVerificationValue(_ context.Context, identifier string) (*models.Verification, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var newest *models.Verification
	for _, v := range r.verifications {
		if identifier != "" && v.Identifier == identifier && (newest == nil || v.CreatedAt.After(newest.CreatedAt)) {
			newest = v
		}
	}
	if newest == nil {
		return nil, notFound("verification")
	}
	c := *newest
	return &c, nil
}

func (r *Repos) DeleteVerificationByIdentifier(_ context.Context, identifier string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, v := range r.verifications {
		if identifier != "" && v.Identifier == identifier {
			delete(r.verifications, id)
		}
	}
	return nil
}

func (r *Repos) ConsumeVerificationValue(_ context.Context, identifier string) (*models.Verification, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var newest *models.Verification
	for _, v := range r.verifications {
		if identifier != "" && v.Identifier == identifier && (newest == nil || v.CreatedAt.After(newest.CreatedAt)) {
			newest = v
		}
	}
	if newest == nil {
		return nil, notFound("verification")
	}
	delete(r.verifications, newest.ID)
	if newest.IsExpired() {
		return nil, notFound("verification")
	}
	c := *newest
	return &c, nil
}

func (r *Repos) DeleteVerificationsByValue(_ context.Context, identifierPrefix, value string) error {
	if identifierPrefix == "" || value == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, v := range r.verifications {
		if v.Value == value && strings.HasPrefix(v.Identifier, identifierPrefix) {
			delete(r.verifications, id)
		}
	}
	return nil
}

func (r *Repos) DeleteExpiredVerifications(_ context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	for id, v := range r.verifications {
		if v.ExpiresAt.Before(now) {
			delete(r.verifications, id)
		}
	}
	return nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// applyUpdates sets the Go fields named by data's keys, converting values the way GORM does
// (e.g. a string into a *string field, nil to the zero value).
func applyUpdates(dst any, data map[string]interface{}) error {
	rv := reflect.ValueOf(dst).Elem()
	for name, val := range data {
		f := rv.FieldByName(name)
		if !f.IsValid() || !f.CanSet() {
			return fmt.Errorf("memory: unknown field %q on %s", name, rv.Type().Name())
		}
		if val == nil {
			f.Set(reflect.Zero(f.Type()))
			continue
		}
		v := reflect.ValueOf(val)
		switch {
		case v.Type().AssignableTo(f.Type()):
			f.Set(v)
		case v.Type().ConvertibleTo(f.Type()):
			f.Set(v.Convert(f.Type()))
		case f.Kind() == reflect.Pointer && v.Type().ConvertibleTo(f.Type().Elem()):
			p := reflect.New(f.Type().Elem())
			p.Elem().Set(v.Convert(f.Type().Elem()))
			f.Set(p)
		case v.Kind() == reflect.Pointer && !v.IsNil() && v.Elem().Type().ConvertibleTo(f.Type()):
			f.Set(v.Elem().Convert(f.Type()))
		default:
			return fmt.Errorf("memory: cannot assign %T to %s.%s", val, rv.Type().Name(), name)
		}
	}
	return nil
}

func fieldValue(u *models.User, name string) any {
	f := reflect.ValueOf(u).Elem().FieldByName(name)
	if f.Kind() == reflect.Pointer {
		if f.IsNil() {
			return nil
		}
		f = f.Elem()
	}
	return f.Interface()
}

func lessValue(a, b any) bool {
	switch x := a.(type) {
	case time.Time:
		y, _ := b.(time.Time)
		return x.Before(y)
	case bool:
		y, _ := b.(bool)
		return !x && y
	case nil:
		return b != nil
	}
	return fmt.Sprint(a) < fmt.Sprint(b)
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

func page[T any](items []T, pageNum, limit int) []T {
	offset := 0
	if pageNum > 1 {
		offset = (pageNum - 1) * limit
	}
	if offset >= len(items) {
		return []T{}
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	return items[offset:end]
}
