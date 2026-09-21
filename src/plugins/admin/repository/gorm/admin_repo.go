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
	db := gormutil.GetDB(ctx, r.db).Model(&models.User{})

	// Global / Field Search
	if input.SearchValue != nil && *input.SearchValue != "" {
		val := "%" + strings.ToLower(*input.SearchValue) + "%"
		if input.SearchField != nil && *input.SearchField != "" {
			col, ok := resolveUserColumn(*input.SearchField)
			if ok {
				db = db.Where(fmt.Sprintf("LOWER(%s) LIKE ?", col), val)
			}
		} else {
			// Search across name and email by default
			db = db.Where("LOWER(first_name) LIKE ? OR LOWER(last_name) LIKE ? OR LOWER(email) LIKE ?", val, val, val)
		}
	}

	// Filter operator & field
	if input.FilterField != nil && *input.FilterField != "" && input.FilterValue != nil {
		col, ok := resolveUserColumn(*input.FilterField)
		if ok {
			op := "eq"
			if input.FilterOperator != nil && *input.FilterOperator != "" {
				op = strings.ToLower(*input.FilterOperator)
			}
			db = applyFilterOperator(db, col, op, *input.FilterValue)
		}
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("gorm/admin: count users: %w", err)
	}

	// Sorting
	sortBy := "created_at"
	if input.SortBy != nil && *input.SortBy != "" {
		if col, ok := resolveUserColumn(*input.SortBy); ok {
			sortBy = col
		}
	}
	sortDir := "desc"
	if input.SortDirection != nil && strings.ToLower(*input.SortDirection) == "asc" {
		sortDir = "asc"
	}

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
	err := db.Order(fmt.Sprintf("%s %s", sortBy, sortDir)).
		Limit(limit).
		Offset(offset).
		Find(&users).Error
	if err != nil {
		return nil, 0, fmt.Errorf("gorm/admin: list users: %w", err)
	}

	return users, total, nil
}

func applyFilterOperator(db *gorm.DB, col, op, val string) *gorm.DB {
	switch op {
	case "eq", "=":
		if col == "banned" || col == "email_verified" {
			b := strings.ToLower(val) == "true" || val == "1"
			return db.Where(fmt.Sprintf("%s = ?", col), b)
		}
		return db.Where(fmt.Sprintf("%s = ?", col), val)
	case "ne", "!=":
		if col == "banned" || col == "email_verified" {
			b := strings.ToLower(val) == "true" || val == "1"
			return db.Where(fmt.Sprintf("%s != ?", col), b)
		}
		return db.Where(fmt.Sprintf("%s != ?", col), val)
	case "lt", "<":
		return db.Where(fmt.Sprintf("%s < ?", col), val)
	case "lte", "<=":
		return db.Where(fmt.Sprintf("%s <= ?", col), val)
	case "gt", ">":
		return db.Where(fmt.Sprintf("%s > ?", col), val)
	case "gte", ">=":
		return db.Where(fmt.Sprintf("%s >= ?", col), val)
	case "contains":
		return db.Where(fmt.Sprintf("LOWER(%s) LIKE ?", col), "%"+strings.ToLower(val)+"%")
	case "starts_with":
		return db.Where(fmt.Sprintf("LOWER(%s) LIKE ?", col), strings.ToLower(val)+"%")
	case "ends_with":
		return db.Where(fmt.Sprintf("LOWER(%s) LIKE ?", col), "%"+strings.ToLower(val))
	default:
		return db.Where(fmt.Sprintf("%s = ?", col), val)
	}
}

func resolveUserColumn(field string) (string, bool) {
	switch strings.ToLower(strings.ReplaceAll(field, "_", "")) {
	case "id":
		return "id", true
	case "name", "firstname":
		return "first_name", true
	case "lastname":
		return "last_name", true
	case "email":
		return "email", true
	case "emailverified":
		return "email_verified", true
	case "role":
		return "role", true
	case "banned":
		return "banned", true
	case "banreason":
		return "ban_reason", true
	case "banexpires":
		return "ban_expires", true
	case "createdat":
		return "created_at", true
	case "updatedat":
		return "updated_at", true
	case "lastloginat":
		return "last_login_at", true
	default:
		return "", false
	}
}

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
			ProviderId: "credential",
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
	err := db.Where("user_id = ? AND provider_id = ?", userID, "credential").Take(&account).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Create account if not present
			newAccount := models.Account{
				Base:       models.Base{ID: models.NewID()},
				UserID:     userID,
				AccountID:  userID,
				ProviderId: "credential",
				Password:   &passwordHash,
			}
			return db.Create(&newAccount).Error
		}
		return fmt.Errorf("gorm/admin: find credential account: %w", err)
	}

	return db.Model(&account).Update("password", passwordHash).Error
}

// SetUserRole changes a user's role and returns the updated record.
func (r *AdminRepo) SetUserRole(ctx context.Context, userID string, role enums.Role) (*models.User, error) {
	db := getDB(ctx, r.db)
	var user models.User
	err := db.Where("id = ?", userID).Take(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, autherr.ErrUserNotFound
		}
		return nil, fmt.Errorf("gorm/admin: get user for role update: %w", err)
	}

	if err := db.Model(&user).Update("role", role).Error; err != nil {
		return nil, fmt.Errorf("gorm/admin: update user role: %w", err)
	}
	user.Role = role
	return &user, nil
}

// BanUser marks a user as banned with optional reason and expiry.
func (r *AdminRepo) BanUser(ctx context.Context, userID string, reason *string, expiresAt *time.Time) (*models.User, error) {
	db := getDB(ctx, r.db)
	var user models.User
	err := db.Where("id = ?", userID).Take(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, autherr.ErrUserNotFound
		}
		return nil, fmt.Errorf("gorm/admin: get user for ban: %w", err)
	}

	updates := map[string]interface{}{
		"banned":      true,
		"ban_reason":  reason,
		"ban_expires": expiresAt,
		"updated_at":  time.Now().UTC(),
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
	err := db.Where("id = ?", userID).Take(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, autherr.ErrUserNotFound
		}
		return nil, fmt.Errorf("gorm/admin: get user for unban: %w", err)
	}

	updates := map[string]interface{}{
		"banned":      false,
		"ban_reason":  nil,
		"ban_expires": nil,
		"updated_at":  time.Now().UTC(),
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
	return db.Transaction(func(tx *gorm.DB) error {
		// Delete sessions
		if err := tx.Where("user_id = ?", userID).Delete(&models.Session{}).Error; err != nil {
			return fmt.Errorf("delete sessions: %w", err)
		}
		// Delete accounts
		if err := tx.Where("user_id = ?", userID).Delete(&models.Account{}).Error; err != nil {
			return fmt.Errorf("delete accounts: %w", err)
		}
		// Delete user
		if err := tx.Where("id = ?", userID).Delete(&models.User{}).Error; err != nil {
			return fmt.Errorf("delete user: %w", err)
		}
		return nil
	})
}

// GetUserByID retrieves a user by ID.
func (r *AdminRepo) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	db := getDB(ctx, r.db)
	var user models.User
	err := db.Where("id = ?", id).Take(&user).Error
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
	err := db.Where("email = ?", email).Take(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, autherr.ErrUserNotFound
		}
		return nil, fmt.Errorf("gorm/admin: get user by email: %w", err)
	}
	return &user, nil
}
