package gormauth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/common/dtos"
	loc_errors "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
	err := gormutil.GetDB(ctx, r.db).Where(userByID(id), "ID").Take(&user).Error
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
		Where(gormutil.IEq(r.db, &models.User{}, "Email", email)).
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
		Where(userByID(id), "ID").
		Updates(data)
	if result.Error != nil {
		return nil, fmt.Errorf("gorm/user: update: %w", result.Error)
	}
	// Reload updated record
	if err := gormutil.GetDB(ctx, r.db).Where(userByID(id), "ID").Take(&user).Error; err != nil {
		return nil, fmt.Errorf("gorm/user: reload after update: %w", err)
	}
	return &user, nil
}

func (r *UserRepo) DeleteUser(ctx context.Context, id string) error {
	now := models.TimeNow()
	tombstoneEmail := models.AnonymizeEmail(id, now)
	result := gormutil.GetDB(ctx, r.db).
		Model(&models.User{}).
		Where(userByID(id), "ID").
		Updates(map[string]interface{}{
			"DeletedAt": now,
			"Email":     tombstoneEmail,
		})
	if result.Error != nil {
		return fmt.Errorf("gorm/user: delete: %w", result.Error)
	}
	return nil
}

func (r *UserRepo) ListUsers(ctx context.Context, filter repo_interfaces.UserFilter, pagi dtos.PaginationInput) ([]models.User, int64, error) {
	user := &models.User{}
	query := gormutil.GetDB(ctx, r.db).Model(user)

	if filter.Email != nil {
		query = query.Where(gormutil.ILike(r.db, user, "Email", "%"+*filter.Email+"%"))
	}
	if filter.Role != nil {
		query = query.Where(clause.Eq{Column: gormutil.Col(r.db, user, "Role"), Value: *filter.Role})
	}
	if filter.Banned != nil {
		query = query.Where(clause.Eq{Column: gormutil.Col(r.db, user, "Banned"), Value: *filter.Banned})
	}
	if filter.SearchField != nil && filter.SearchValue != nil {
		field, ok := userListField(*filter.SearchField)
		if !ok {
			return nil, 0, fmt.Errorf("gorm/user: invalid search field")
		}
		query = query.Where(gormutil.ILike(r.db, user, field, "%"+*filter.SearchValue+"%"))
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("gorm/user: count: %w", err)
	}

	sortBy := "CreatedAt"
	if pagi.SortBy != "" {
		field, ok := userListField(pagi.SortBy)
		if !ok {
			return nil, 0, fmt.Errorf("gorm/user: invalid sort field")
		}
		sortBy = field
	}

	limit := 20
	if pagi.Limit > 0 {
		limit = pagi.Limit
	}

	var users []models.User
	err := query.
		Order(gormutil.OrderBy(r.db, user, sortBy, strings.ToLower(pagi.SortDir) != "asc")).
		Limit(limit).
		Offset(pagi.Page).
		Find(&users).Error
	if err != nil {
		return nil, 0, fmt.Errorf("gorm/user: list: %w", err)
	}
	return users, total, nil
}

// userByID is a struct condition on the primary key; pass "ID" to Where so an empty id matches nothing.
func userByID(id string) *models.User {
	return &models.User{Base: models.Base{ID: id}}
}

// userListField maps an allowed sort/search name (API or column spelling) to its Go field.
func userListField(field string) (string, bool) {
	switch strings.ToLower(field) {
	case "id":
		return "ID", true
	case "name":
		return "Name", true
	case "email":
		return "Email", true
	case "role":
		return "Role", true
	case "banned":
		return "Banned", true
	case "createdat", "created_at":
		return "CreatedAt", true
	case "updatedat", "updated_at":
		return "UpdatedAt", true
	case "lastloginat", "last_login_at":
		return "LastLoginAt", true
	default:
		return "", false
	}
}
