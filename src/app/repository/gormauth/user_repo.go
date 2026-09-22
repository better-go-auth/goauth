package gormauth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	loc_errors "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/common/dtos"
	"gorm.io/gorm"
)

// UserRepo implements repoimpl.IUserRepo using GORM.
type UserRepo struct {
	db *gorm.DB
}

// NewUserRepo creates a new GORM-backed UserRepo.
func NewUserRepo(db *gorm.DB) repo_interfaces.IUserRepo {
	return &UserRepo{db: db}
}

func (r *UserRepo) CreateUser(ctx context.Context, user *models.User) (*models.User, error) {
	if user.ID == "" {
		user.ID = models.NewID()
	}
	if err := gormutil.GetDB(ctx, r.db).Create(user).Error; err != nil {
		return nil, fmt.Errorf("gorm/user: create: %w", err)
	}
	return user, nil
}

func (r *UserRepo) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	var user models.User
	err := gormutil.GetDB(ctx, r.db).Where("id = ? AND deleted_at IS NULL", id).Take(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, loc_errors.NotFoundErr("gorm/user: not found")
		}
		return nil, fmt.Errorf("gorm/user: get by id: %w", err)
	}
	return &user, nil
}

func (r *UserRepo) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	err := gormutil.GetDB(ctx, r.db).
		Where("LOWER(email) = LOWER(?) AND deleted_at IS NULL", email).
		Take(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, loc_errors.NotFoundErr("gorm/user: not found")
		}
		return nil, fmt.Errorf("gorm/user: get by email: %w", err)
	}
	return &user, nil
}

func (r *UserRepo) UpdateUser(ctx context.Context, id string, data map[string]interface{}) (*models.User, error) {
	var user models.User
	result := gormutil.GetDB(ctx, r.db).
		Model(&user).
		Where("id = ? AND deleted_at IS NULL", id).
		Updates(data)
	if result.Error != nil {
		return nil, fmt.Errorf("gorm/user: update: %w", result.Error)
	}
	// Reload updated record
	if err := gormutil.GetDB(ctx, r.db).Where("id = ?", id).Take(&user).Error; err != nil {
		return nil, fmt.Errorf("gorm/user: reload after update: %w", err)
	}
	return &user, nil
}

func (r *UserRepo) DeleteUser(ctx context.Context, id string) error {
	now := models.TimeNow()
	tombstoneEmail := models.AnonymizeEmail(id, now)
	result := gormutil.GetDB(ctx, r.db).
		Model(&models.User{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"deleted_at": now,
			"email":      tombstoneEmail,
		})
	if result.Error != nil {
		return fmt.Errorf("gorm/user: delete: %w", result.Error)
	}
	return nil
}

func (r *UserRepo) ListUsers(ctx context.Context, filter repo_interfaces.UserFilter, pagi dtos.PaginationInput) ([]models.User, int64, error) {
	query := gormutil.GetDB(ctx, r.db).Model(&models.User{}).Where("deleted_at IS NULL")

	if filter.Email != nil {
		query = query.Where("LOWER(email) LIKE LOWER(?)", "%"+*filter.Email+"%")
	}
	if filter.Role != nil {
		query = query.Where("role = ?", *filter.Role)
	}
	if filter.Banned != nil {
		query = query.Where("banned = ?", *filter.Banned)
	}
	if filter.SearchField != nil && filter.SearchValue != nil {
		col, ok := userListColumn(*filter.SearchField)
		if !ok {
			return nil, 0, fmt.Errorf("gorm/user: invalid search field")
		}
		query = query.Where(fmt.Sprintf("LOWER(%s) LIKE LOWER(?)", col), "%"+*filter.SearchValue+"%")
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("gorm/user: count: %w", err)
	}

	sortBy := "created_at"
	if pagi.SortBy != "" {
		col, ok := userListColumn(pagi.SortBy)
		if !ok {
			return nil, 0, fmt.Errorf("gorm/user: invalid sort field")
		}
		sortBy = col
	}
	sortDir := "desc"
	if strings.ToLower(pagi.SortDir) == "asc" {
		sortDir = "asc"
	}

	limit := 20
	if pagi.Limit > 0 {
		limit = pagi.Limit
	}

	var users []models.User
	err := query.
		Order(fmt.Sprintf("%s %s", sortBy, sortDir)).
		Limit(limit).
		Offset(pagi.Page).
		Find(&users).Error
	if err != nil {
		return nil, 0, fmt.Errorf("gorm/user: list: %w", err)
	}
	return users, total, nil
}

func userListColumn(field string) (string, bool) {
	switch strings.ToLower(field) {
	case "id":
		return "id", true
	case "name":
		return "name", true
	case "email":
		return "email", true
	case "role":
		return "role", true
	case "banned":
		return "banned", true
	case "createdat", "created_at":
		return "created_at", true
	case "updatedat", "updated_at":
		return "updated_at", true
	case "lastloginat", "last_login_at":
		return "last_login_at", true
	default:
		return "", false
	}
}
