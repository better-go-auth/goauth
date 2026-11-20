// Package adapteradmin implements the admin plugin's repository on the storage adapter (InitContext.Adapter):
// the admin plugin has no tables of its own, it reads and writes the core user, session and account models
// (and the admin fields better-auth's admin plugin adds to them), so it works on every backend, in either
// column case and with database-generated ids.
package adapteradmin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/app/repository/adapterrepo"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/enums"
	"github.com/better-go-auth/goauth/src/plugins/admin/dtos"
	"github.com/better-go-auth/goauth/src/plugins/admin/repository"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/schema"
)

// AdminRepo implements repository.IAdminRepo.
type AdminRepo struct {
	a     adapter.Adapter
	repos *adapterrepo.Repos
}

var _ repository.IAdminRepo = (*AdminRepo)(nil)

// New returns the admin repository on a (reg: the registry a was built with, InitContext.Schema).
func New(a adapter.Adapter, reg *schema.Registry) (*AdminRepo, error) {
	if a == nil || reg == nil {
		return nil, errors.New("admin plugin: a storage adapter and the schema registry are required")
	}
	repos, err := adapterrepo.New(a, reg)
	if err != nil {
		return nil, err
	}
	return &AdminRepo{a: a, repos: repos}, nil
}

// NewRepositories returns the admin repository bundle on a (no migrator: the admin fields are part of the
// core user and session models).
func NewRepositories(a adapter.Adapter, reg *schema.Registry) (repository.AdminRepositories, error) {
	r, err := New(a, reg)
	if err != nil {
		return repository.AdminRepositories{}, err
	}
	return repository.AdminRepositories{AdminRepo: r}, nil
}

// userNotFound maps the core repositories' not-found error to better-auth's USER_NOT_FOUND.
func userNotFound(u *models.User, err error) (*models.User, error) {
	if err != nil {
		if pluginkit.IsNotFound(err) {
			return nil, autherr.ErrUserNotFound
		}
		return nil, err
	}
	return u, nil
}

// ─── listing ─────────────────────────────────────────────────────────────────

// userFields maps the API field names admin/list-users accepts (camelCase, any case, underscores ignored)
// to registry field names.
var userFields = map[string]string{
	"id": "id", "name": "name", "firstname": "firstName", "lastname": "lastName", "email": "email",
	"emailverified": "emailVerified", "role": "role", "banned": "banned", "banreason": "banReason",
	"banexpires": "banExpires", "createdat": "createdAt", "updatedat": "updatedAt", "lastloginat": "lastLoginAt",
}

// field resolves an API field name to a registry field the registry has.
func (r *AdminRepo) field(name string) (string, bool) {
	f, ok := userFields[strings.ToLower(strings.ReplaceAll(name, "_", ""))]
	if !ok {
		return "", false
	}
	return r.repos.UserField(f)
}

// filterOps maps better-auth's filterOperator values (and goauth's symbolic aliases) to adapter operators.
var filterOps = map[string]adapter.Op{
	"eq": adapter.Eq, "=": adapter.Eq, "ne": adapter.Ne, "!=": adapter.Ne,
	"lt": adapter.Lt, "<": adapter.Lt, "lte": adapter.Lte, "<=": adapter.Lte,
	"gt": adapter.Gt, ">": adapter.Gt, "gte": adapter.Gte, ">=": adapter.Gte,
	"contains": adapter.Contains, "starts_with": adapter.StartsWith, "ends_with": adapter.EndsWith,
}

// ListUsers searches, filters, and paginates users according to admin criteria.
func (r *AdminRepo) ListUsers(ctx context.Context, input dtos.AdminListUsersInput) ([]models.User, int64, error) {
	var where []adapter.Where
	// Step 1: search: one field, or name / first name / last name / email by default (case-insensitive)
	if input.SearchValue != nil && *input.SearchValue != "" {
		if input.SearchField != nil && *input.SearchField != "" {
			if f, ok := r.field(*input.SearchField); ok {
				where = append(where, adapter.Where{Field: f, Op: adapter.Contains, Value: *input.SearchValue, Insensitive: true})
			}
		} else {
			for _, name := range []string{"name", "firstName", "lastName", "email"} {
				if f, ok := r.repos.UserField(name); ok {
					where = append(where, adapter.Where{Field: f, Op: adapter.Contains, Value: *input.SearchValue, Insensitive: true, Connector: adapter.Or})
				}
			}
		}
	}
	// Step 2: filter (better-auth's filterField / filterOperator / filterValue)
	if input.FilterField != nil && *input.FilterField != "" && input.FilterValue != nil {
		if f, ok := r.field(*input.FilterField); ok {
			op := adapter.Eq
			if input.FilterOperator != nil && *input.FilterOperator != "" {
				if o, known := filterOps[strings.ToLower(*input.FilterOperator)]; known {
					op = o
				}
			}
			var v any = *input.FilterValue
			if f == "banned" || f == "emailVerified" {
				v = strings.EqualFold(*input.FilterValue, "true") || *input.FilterValue == "1"
			}
			if op == adapter.Contains || op == adapter.StartsWith || op == adapter.EndsWith {
				where = append(where, adapter.Where{Field: f, Op: op, Value: *input.FilterValue, Insensitive: true})
			} else {
				where = append(where, adapter.Where{Field: f, Op: op, Value: v})
			}
		}
	}
	// Step 3: total
	total, err := r.repos.CountUsers(ctx, where)
	if err != nil {
		return nil, 0, fmt.Errorf("admin: count users: %w", err)
	}
	// Step 4: order (createdAt, newest first by default) and page
	sortBy := "createdAt"
	if input.SortBy != nil && *input.SortBy != "" {
		if f, ok := r.field(*input.SortBy); ok {
			sortBy = f
		}
	}
	desc := input.SortDirection == nil || !strings.EqualFold(*input.SortDirection, "asc")
	limit := 20
	if input.Limit != nil && *input.Limit > 0 {
		limit = *input.Limit
	}
	offset := 0
	if input.Offset != nil && *input.Offset >= 0 {
		offset = *input.Offset
	}
	users, err := r.repos.FindUsers(ctx, adapter.Query{
		Where: where, Limit: limit, Offset: offset,
		Sort: []adapter.SortBy{{Field: sortBy, Desc: desc}, {Field: "id", Desc: desc}},
	})
	if err != nil {
		return nil, 0, fmt.Errorf("admin: list users: %w", err)
	}
	return users, total, nil
}

// ─── users ───────────────────────────────────────────────────────────────────

// CreateUserWithAccount inserts a new user and its credential account in one transaction.
func (r *AdminRepo) CreateUserWithAccount(ctx context.Context, user *models.User, passwordHash string) (*models.User, error) {
	err := r.a.Transaction(ctx, func(ctx context.Context) error {
		// Step 1: the user (the stored row, with its generated id, is copied back into user)
		if _, err := r.repos.CreateUser(ctx, user); err != nil {
			return fmt.Errorf("create user: %w", err)
		}
		// Step 2: the credential account holding the password hash
		account := &models.Account{
			Base:       models.Base{ID: models.NewID()},
			UserID:     user.ID,
			AccountID:  user.ID,
			ProviderID: models.ProvCredential,
			Password:   &passwordHash,
		}
		if _, err := r.repos.CreateAccount(ctx, account); err != nil {
			return fmt.Errorf("create credential account: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("admin: create user with account: %w", err)
	}
	return user, nil
}

// SetUserPassword updates the password hash of the user's credential account (created when missing).
func (r *AdminRepo) SetUserPassword(ctx context.Context, userID, passwordHash string) error {
	// Step 1: the credential account
	acc, err := pluginkit.AcceptNotFound(r.repos.FindAccountByUserAndProvider(ctx, userID, models.ProvCredential))
	if err != nil {
		return fmt.Errorf("admin: find credential account: %w", err)
	}
	// Step 2: create it when the user has none
	if acc == nil {
		_, err := r.repos.CreateAccount(ctx, &models.Account{
			Base:       models.Base{ID: models.NewID()},
			UserID:     userID,
			AccountID:  userID,
			ProviderID: models.ProvCredential,
			Password:   &passwordHash,
		})
		return err
	}
	// Step 3: else replace the hash
	_, err = r.repos.UpdateAccount(ctx, acc.ID, map[string]any{"password": passwordHash})
	return err
}

// SetUserRole changes a user's role and returns the updated record.
func (r *AdminRepo) SetUserRole(ctx context.Context, userID string, role enums.Role) (*models.User, error) {
	return r.UpdateUser(ctx, userID, map[string]any{"role": string(role)})
}

// BanUser marks a user as banned with optional reason and expiry.
func (r *AdminRepo) BanUser(ctx context.Context, userID string, reason *string, expiresAt *time.Time) (*models.User, error) {
	return r.UpdateUser(ctx, userID, map[string]any{"banned": true, "banReason": reason, "banExpires": expiresAt})
}

// UnbanUser clears a user's ban status.
func (r *AdminRepo) UnbanUser(ctx context.Context, userID string) (*models.User, error) {
	return r.UpdateUser(ctx, userID, map[string]any{"banned": false, "banReason": nil, "banExpires": nil})
}

// RemoveUser deletes a user, their linked accounts, and their sessions (soft: tombstones the user).
func (r *AdminRepo) RemoveUser(ctx context.Context, userID string, soft bool) error {
	// Step 1: default: remove the user row like better-auth (with its sessions and accounts)
	if !soft {
		return r.repos.DeleteUser(ctx, userID)
	}
	// Step 2: soft delete: sessions and accounts go, the user row stays as a tombstone (anonymized email,
	// released phone number and username, same as the core SoftDeleteUser)
	return r.a.Transaction(ctx, func(ctx context.Context) error {
		if err := r.repos.DeleteUserSessions(ctx, userID); err != nil {
			return fmt.Errorf("delete sessions: %w", err)
		}
		if err := r.repos.DeleteAccounts(ctx, userID); err != nil {
			return fmt.Errorf("delete accounts: %w", err)
		}
		return r.repos.SoftDeleteUser(ctx, userID)
	})
}

// GetUserByID retrieves a live user by ID.
func (r *AdminRepo) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	return userNotFound(r.repos.FindUserByID(ctx, id))
}

// GetUserByEmail retrieves a live user by email (case-insensitive).
func (r *AdminRepo) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	return userNotFound(r.repos.FindUserByEmail(ctx, email))
}

// UpdateUser updates user fields (Go field names, registry names or columns) by ID.
func (r *AdminRepo) UpdateUser(ctx context.Context, userID string, updates map[string]interface{}) (*models.User, error) {
	return userNotFound(r.repos.UpdateUser(ctx, userID, updates))
}

// ─── sessions ────────────────────────────────────────────────────────────────

// ListUserSessions returns the user's unexpired sessions, newest first.
func (r *AdminRepo) ListUserSessions(ctx context.Context, userID string) ([]models.Session, error) {
	sessions, err := r.repos.FindSessions(ctx, adapter.Query{
		Where: []adapter.Where{{Field: "userId", Value: userID}, {Field: "expiresAt", Op: adapter.Gt, Value: models.TimeNow()}},
		Sort:  []adapter.SortBy{{Field: "createdAt", Desc: true}, {Field: "id", Desc: true}},
	})
	if err != nil {
		return nil, fmt.Errorf("admin: list user sessions: %w", err)
	}
	return sessions, nil
}

// RevokeUserSession deletes a single session by its ID or token.
func (r *AdminRepo) RevokeUserSession(ctx context.Context, sessionID, sessionToken string) error {
	switch {
	case sessionID != "":
		return r.repos.DeleteSessionByID(ctx, sessionID)
	case sessionToken != "":
		return r.repos.DeleteSession(ctx, sessionToken)
	}
	return autherr.New(autherr.BadRequest, "sessionToken or id is required", 400)
}

// RevokeUserSessions deletes all sessions belonging to a specific user.
func (r *AdminRepo) RevokeUserSessions(ctx context.Context, userID string) error {
	return r.repos.DeleteUserSessions(ctx, userID)
}

// CreateImpersonationSession stores an impersonation session (impersonatedBy set by the caller).
func (r *AdminRepo) CreateImpersonationSession(ctx context.Context, session *models.Session) (*models.Session, error) {
	created, err := r.repos.CreateSession(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("admin: create impersonation session: %w", err)
	}
	return created, nil
}

// GetSessionByID retrieves a session by its ID, with its user.
func (r *AdminRepo) GetSessionByID(ctx context.Context, id string) (*models.Session, error) {
	// Step 1: the session
	s, err := r.repos.FindSessionByID(ctx, id)
	if err != nil {
		if pluginkit.IsNotFound(err) {
			return nil, autherr.ErrSessionNotFound
		}
		return nil, err
	}
	// Step 2: its user (left nil when it is gone)
	if u, err := pluginkit.AcceptNotFound(r.repos.FindUserByID(ctx, s.UserID)); err == nil {
		s.User = u
	}
	return s, nil
}

// DeleteSessionByID deletes a session by ID.
func (r *AdminRepo) DeleteSessionByID(ctx context.Context, id string) error {
	return r.repos.DeleteSessionByID(ctx, id)
}
