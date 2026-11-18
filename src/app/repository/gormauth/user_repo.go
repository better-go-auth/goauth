package gormauth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	loc_errors "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/dtos"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// UserRepo implements repoimpl.IUserRepo using GORM.
type UserRepo struct {
	db         *gorm.DB
	generateID func() string
}

// NewUserRepo creates a new GORM-backed UserRepo.
func NewUserRepo(db *gorm.DB, opts ...RepoOption) repo_interfaces.IUserRepo {
	cfg := &RepoConfig{}
	for _, o := range opts {
		o(cfg)
	}
	return &UserRepo{db: db, generateID: cfg.GenerateID}
}

func (r *UserRepo) newID() string {
	if r.generateID != nil {
		return r.generateID()
	}
	return models.NewID()
}

func (r *UserRepo) CreateUser(ctx context.Context, user *models.User) (*models.User, error) {
	// Step 1: Generate ID if not already provided
	if user.ID == "" {
		user.ID = r.newID()
	}
	// Step 2: Prepare save (normalize email and set display name)
	user.PrepareSave()
	// Step 3: Insert user record
	if err := gormutil.GetDB(ctx, r.db).Create(user).Error; err != nil {
		return nil, fmt.Errorf("gorm/user: create: %w", err)
	}
	return user, nil
}

func (r *UserRepo) FindUserByID(ctx context.Context, id string) (*models.User, error) {
	var user models.User
	// Step 1: Query user by primary key and exclude soft-deleted records
	err := gormutil.GetDB(ctx, r.db).
		Where(userByID(id), "ID").
		Where("deleted_at IS NULL").
		Take(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, loc_errors.NotFoundErr("gorm/user: not found")
		}
		return nil, fmt.Errorf("gorm/user: get by id: %w", err)
	}
	return &user, nil
}

func (r *UserRepo) FindUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	// Step 1: Query user by case-insensitive email and exclude soft-deleted records
	err := gormutil.GetDB(ctx, r.db).
		Where(gormutil.IEq(r.db, &models.User{}, "Email", email)).
		Where("deleted_at IS NULL").
		Take(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, loc_errors.NotFoundErr("gorm/user: not found")
		}
		return nil, fmt.Errorf("gorm/user: get by email: %w", err)
	}
	return &user, nil
}

// FindUserByPhoneNumber looks up a live user by its exact phone number (phone-number plugin).
func (r *UserRepo) FindUserByPhoneNumber(ctx context.Context, phoneNumber string) (*models.User, error) {
	var user models.User
	if phoneNumber == "" {
		return nil, loc_errors.NotFoundErr("gorm/user: not found")
	}
	// Step 1: Query by phone number and exclude soft-deleted records
	err := gormutil.GetDB(ctx, r.db).
		Where(&models.User{UserDto: models.UserDto{PhoneNumber: &phoneNumber}}, "PhoneNumber").
		Where("deleted_at IS NULL").
		Take(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, loc_errors.NotFoundErr("gorm/user: not found")
		}
		return nil, fmt.Errorf("gorm/user: get by phone number: %w", err)
	}
	return &user, nil
}

// FindUserByUsername looks up a live user by its exact (already normalized) username (username plugin).
func (r *UserRepo) FindUserByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	if username == "" {
		return nil, loc_errors.NotFoundErr("gorm/user: not found")
	}
	// Step 1: Query by username and exclude soft-deleted records
	err := gormutil.GetDB(ctx, r.db).
		Where(&models.User{UserDto: models.UserDto{Username: &username}}, "Username").
		Where("deleted_at IS NULL").
		Take(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, loc_errors.NotFoundErr("gorm/user: not found")
		}
		return nil, fmt.Errorf("gorm/user: get by username: %w", err)
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

// DeleteUser hard-deletes the user row after its sessions and accounts (better-auth's cascade), in one
// transaction so the foreign keys from session/account never point at a missing user.
func (r *UserRepo) DeleteUser(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	err := gormutil.GetDB(ctx, r.db).Transaction(func(tx *gorm.DB) error {
		// Step 1: sessions of the user (and sessions where the user impersonates someone)
		if err := tx.Where(&models.Session{UserID: id}, "UserID").Delete(&models.Session{}).Error; err != nil {
			return err
		}
		if err := tx.Where(&models.Session{ImpersonatedBy: &id}, "ImpersonatedBy").Delete(&models.Session{}).Error; err != nil {
			return err
		}
		// Step 2: linked accounts
		if err := tx.Where(&models.Account{UserID: id}, "UserID").Delete(&models.Account{}).Error; err != nil {
			return err
		}
		// Step 3: the user row itself
		return tx.Where(userByID(id), "ID").Delete(&models.User{}).Error
	})
	if err != nil {
		return fmt.Errorf("gorm/user: delete: %w", err)
	}
	return nil
}

// SoftDeleteUser keeps the row as a tombstone: deletedAt is set and the unique columns are released.
func (r *UserRepo) SoftDeleteUser(ctx context.Context, id string) error {
	now := models.TimeNow()
	tombstoneEmail := models.AnonymizeEmail(id, now)
	result := gormutil.GetDB(ctx, r.db).
		Model(&models.User{}).
		Where(userByID(id), "ID").
		Updates(map[string]interface{}{
			"DeletedAt": now,
			"Email":     tombstoneEmail,
			// release the unique phone number so it can be registered again
			"PhoneNumber": nil,
			// release the unique username too (username plugin)
			"Username": nil,
		})
	if result.Error != nil {
		return fmt.Errorf("gorm/user: soft delete: %w", result.Error)
	}
	return nil
}

func (r *UserRepo) ListUsers(ctx context.Context, filter repo_interfaces.UserFilter, pagi dtos.PaginationInput) ([]models.User, int64, error) {
	user := &models.User{}
	// Step 1: Build base query excluding soft-deleted records
	query := gormutil.GetDB(ctx, r.db).Model(user).Where("deleted_at IS NULL")

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
		field, ok := repo_interfaces.UserListField(*filter.SearchField)
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
		field, ok := repo_interfaces.UserListField(pagi.SortBy)
		if !ok {
			return nil, 0, fmt.Errorf("gorm/user: invalid sort field")
		}
		sortBy = field
	}

	limit := 20
	if pagi.Limit > 0 {
		limit = pagi.Limit
	}
	offset := 0
	if pagi.Page > 1 {
		offset = (pagi.Page - 1) * limit
	}

	var users []models.User
	err := query.
		Order(gormutil.OrderBy(r.db, user, sortBy, strings.ToLower(pagi.SortDir) != "asc")).
		Limit(limit).
		Offset(offset).
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
