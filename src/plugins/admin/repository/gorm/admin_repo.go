package gormadmin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/enums"
	"github.com/better-go-auth/goauth/src/plugins/admin/dtos"
	"github.com/better-go-auth/goauth/src/plugins/admin/repository"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// AdminRepo implements repository.IAdminRepo using GORM.
type AdminRepo struct {
	db *gorm.DB
}

var _ repository.IAdminRepo = (*AdminRepo)(nil)

// NewAdminRepo creates a new GORM-backed AdminRepo.
func NewAdminRepo(db *gorm.DB) repository.IAdminRepo {
	return &AdminRepo{db: db}
}

// ListUsers searches, filters, and paginates users according to admin criteria.
func (r *AdminRepo) ListUsers(ctx context.Context, input dtos.AdminListUsersInput) ([]models.User, int64, error) {
	user := &models.User{}
	db := gormutil.GetDB(ctx, r.db).Model(user)

	// Global / Field Search
	if input.SearchValue != nil && *input.SearchValue != "" {
		val := "%" + *input.SearchValue + "%"
		if input.SearchField != nil && *input.SearchField != "" {
			if field, ok := resolveUserField(*input.SearchField); ok {
				db = db.Where(gormutil.ILike(r.db, user, field, val))
			}
		} else {
			// Search across name and email by default
			db = db.Where(clause.Or(
				gormutil.ILike(r.db, user, "Name", val),
				gormutil.ILike(r.db, user, "FirstName", val),
				gormutil.ILike(r.db, user, "LastName", val),
				gormutil.ILike(r.db, user, "Email", val),
			))
		}
	}

	// Filter operator & field
	if input.FilterField != nil && *input.FilterField != "" && input.FilterValue != nil {
		if field, ok := resolveUserField(*input.FilterField); ok {
			op := "eq"
			if input.FilterOperator != nil && *input.FilterOperator != "" {
				op = strings.ToLower(*input.FilterOperator)
			}
			db = db.Where(r.filterExpr(field, op, *input.FilterValue))
		}
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("gorm/admin: count users: %w", err)
	}

	// Sorting
	sortBy := "CreatedAt"
	if input.SortBy != nil && *input.SortBy != "" {
		if field, ok := resolveUserField(*input.SortBy); ok {
			sortBy = field
		}
	}
	desc := input.SortDirection == nil || strings.ToLower(*input.SortDirection) != "asc"

	// Pagination
	limit := 20
	if input.Limit != nil && *input.Limit > 0 {
		limit = *input.Limit
	}
	offset := 0
	if input.Offset != nil && *input.Offset >= 0 {
		offset = *input.Offset
	}

	var users []models.User
	err := db.Order(gormutil.OrderBy(r.db, user, sortBy, desc)).
		Limit(limit).
		Offset(offset).
		Find(&users).Error
	if err != nil {
		return nil, 0, fmt.Errorf("gorm/admin: list users: %w", err)
	}

	return users, total, nil
}

// filterExpr builds better-auth's filterOperator condition on a user field.
func (r *AdminRepo) filterExpr(field, op, val string) clause.Expression {
	col := gormutil.Col(r.db, &models.User{}, field)
	var v any = val
	if field == "Banned" || field == "EmailVerified" {
		v = strings.ToLower(val) == "true" || val == "1"
	}
	switch op {
	case "ne", "!=":
		return clause.Neq{Column: col, Value: v}
	case "lt", "<":
		return clause.Lt{Column: col, Value: v}
	case "lte", "<=":
		return clause.Lte{Column: col, Value: v}
	case "gt", ">":
		return clause.Gt{Column: col, Value: v}
	case "gte", ">=":
		return clause.Gte{Column: col, Value: v}
	case "contains":
		return gormutil.ILike(r.db, &models.User{}, field, "%"+val+"%")
	case "starts_with":
		return gormutil.ILike(r.db, &models.User{}, field, val+"%")
	case "ends_with":
		return gormutil.ILike(r.db, &models.User{}, field, "%"+val)
	default:
		return clause.Eq{Column: col, Value: v}
	}
}

// resolveUserField maps an allowed API field name to its Go field on models.User.
func resolveUserField(field string) (string, bool) {
	switch strings.ToLower(strings.ReplaceAll(field, "_", "")) {
	case "id":
		return "ID", true
	case "name":
		return "Name", true
	case "firstname":
		return "FirstName", true
	case "lastname":
		return "LastName", true
	case "email":
		return "Email", true
	case "emailverified":
		return "EmailVerified", true
	case "role":
		return "Role", true
	case "banned":
		return "Banned", true
	case "banreason":
		return "BanReason", true
	case "banexpires":
		return "BanExpires", true
	case "createdat":
		return "CreatedAt", true
	case "updatedat":
		return "UpdatedAt", true
	case "lastloginat":
		return "LastLoginAt", true
	default:
		return "", false
	}
}

func userByID(id string) *models.User { return &models.User{Base: models.Base{ID: id}} }

// CreateUserWithAccount inserts a new user and credential account in a transaction.
func (r *AdminRepo) CreateUserWithAccount(ctx context.Context, user *models.User, passwordHash string) (*models.User, error) {
	db := getDB(ctx, r.db)

	err := db.Transaction(func(tx *gorm.DB) error {
		if user.ID == "" {
			user.ID = models.NewID()
		}
		if err := tx.Create(user).Error; err != nil {
			return fmt.Errorf("create user: %w", err)
		}

		account := &models.Account{
			Base:       models.Base{ID: models.NewID()},
			UserID:     user.ID,
			AccountID:  user.ID,
			ProviderID: "credential",
			Password:   &passwordHash,
		}
		if err := tx.Create(account).Error; err != nil {
			return fmt.Errorf("create credential account: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("gorm/admin: create user with account: %w", err)
	}
	return user, nil
}

// SetUserPassword updates the password hash for a user's credential account.
func (r *AdminRepo) SetUserPassword(ctx context.Context, userID, passwordHash string) error {
	db := getDB(ctx, r.db)

	var account models.Account
	err := db.Where(&models.Account{UserID: userID, ProviderID: models.ProvCredential}, "UserID", "ProviderID").Take(&account).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Create account if not present
			newAccount := models.Account{
				Base:       models.Base{ID: models.NewID()},
				UserID:     userID,
				AccountID:  userID,
				ProviderID: "credential",
				Password:   &passwordHash,
			}
			return db.Create(&newAccount).Error
		}
		return fmt.Errorf("gorm/admin: find credential account: %w", err)
	}

	return db.Model(&account).Update("Password", passwordHash).Error
}

// SetUserRole changes a user's role and returns the updated record.
func (r *AdminRepo) SetUserRole(ctx context.Context, userID string, role enums.Role) (*models.User, error) {
	db := getDB(ctx, r.db)
	var user models.User
	err := db.Where(userByID(userID), "ID").Take(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, autherr.ErrUserNotFound
		}
		return nil, fmt.Errorf("gorm/admin: get user for role update: %w", err)
	}

	if err := db.Model(&user).Update("Role", role).Error; err != nil {
		return nil, fmt.Errorf("gorm/admin: update user role: %w", err)
	}
	user.Role = role
	return &user, nil
}

// BanUser marks a user as banned with optional reason and expiry.
func (r *AdminRepo) BanUser(ctx context.Context, userID string, reason *string, expiresAt *time.Time) (*models.User, error) {
	db := getDB(ctx, r.db)
	var user models.User
	err := db.Where(userByID(userID), "ID").Take(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, autherr.ErrUserNotFound
		}
		return nil, fmt.Errorf("gorm/admin: get user for ban: %w", err)
	}

	updates := map[string]interface{}{
		"Banned":     true,
		"BanReason":  reason,
		"BanExpires": expiresAt,
		"UpdatedAt":  time.Now().UTC(),
	}
	if err := db.Model(&user).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("gorm/admin: ban user: %w", err)
	}

	user.Banned = true
	user.BanReason = reason
	user.BanExpires = expiresAt
	return &user, nil
}

// UnbanUser clears a user's ban status.
func (r *AdminRepo) UnbanUser(ctx context.Context, userID string) (*models.User, error) {
	db := getDB(ctx, r.db)
	var user models.User
	err := db.Where(userByID(userID), "ID").Take(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, autherr.ErrUserNotFound
		}
		return nil, fmt.Errorf("gorm/admin: get user for unban: %w", err)
	}

	updates := map[string]interface{}{
		"Banned":     false,
		"BanReason":  nil,
		"BanExpires": nil,
		"UpdatedAt":  time.Now().UTC(),
	}
	if err := db.Model(&user).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("gorm/admin: unban user: %w", err)
	}

	user.Banned = false
	user.BanReason = nil
	user.BanExpires = nil
	return &user, nil
}

// RemoveUser deletes a user, their linked accounts, and their active sessions.
func (r *AdminRepo) RemoveUser(ctx context.Context, userID string) error {
	db := getDB(ctx, r.db)
	now := time.Now().UTC()
	tombstoneEmail := models.AnonymizeEmail(userID, now)
	return db.Transaction(func(tx *gorm.DB) error {
		// Delete sessions
		if err := tx.Where(&models.Session{UserID: userID}, "UserID").Delete(&models.Session{}).Error; err != nil {
			return fmt.Errorf("delete sessions: %w", err)
		}
		// Delete accounts
		if err := tx.Where(&models.Account{UserID: userID}, "UserID").Delete(&models.Account{}).Error; err != nil {
			return fmt.Errorf("delete accounts: %w", err)
		}
		// Anonymize email and soft-delete user
		if err := tx.Model(&models.User{}).Where(userByID(userID), "ID").Updates(map[string]interface{}{
			"DeletedAt": now,
			"Email":     tombstoneEmail,
		}).Error; err != nil {
			return fmt.Errorf("delete user: %w", err)
		}
		return nil
	})
}

// GetUserByID retrieves a user by ID.
func (r *AdminRepo) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	db := getDB(ctx, r.db)
	var user models.User
	err := db.Where(userByID(id), "ID").Take(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, autherr.ErrUserNotFound
		}
		return nil, fmt.Errorf("gorm/admin: get user by id: %w", err)
	}
	return &user, nil
}

// GetUserByEmail retrieves a user by email.
func (r *AdminRepo) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	db := getDB(ctx, r.db)
	var user models.User
	err := db.Where(gormutil.IEq(r.db, &models.User{}, "Email", email)).Take(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, autherr.ErrUserNotFound
		}
		return nil, fmt.Errorf("gorm/admin: get user by email: %w", err)
	}
	return &user, nil
}
