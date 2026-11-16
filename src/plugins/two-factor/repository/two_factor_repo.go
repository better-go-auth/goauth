// Package repository persists the two-factor plugin's rows.
package repository

import (
	"context"
	"errors"

	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/models/migration"
	tfmodels "github.com/better-go-auth/goauth/src/plugins/two-factor/models"
	"gorm.io/gorm"
)

// ITwoFactorRepo stores the twoFactor rows.
type ITwoFactorRepo interface {
	Migrator() migration.IMigrator
	// FindByUserID returns the user's row, or (nil, nil).
	FindByUserID(ctx context.Context, userID string) (*tfmodels.TwoFactor, error)
	Create(ctx context.Context, row *tfmodels.TwoFactor) error
	// DeleteByUserID deletes every row of the user.
	DeleteByUserID(ctx context.Context, userID string) error
	// SetVerified marks the row verified.
	SetVerified(ctx context.Context, id string) error
	// UpdateBackupCodes replaces the stored backup codes.
	UpdateBackupCodes(ctx context.Context, id, backupCodes string) error
	// SwapBackupCodes replaces the stored backup codes only when they still equal old (compare-and-swap
	// so one backup code cannot be used twice concurrently). It reports whether a row was updated.
	SwapBackupCodes(ctx context.Context, id, old, updated string) (bool, error)
}

type gormRepo struct {
	db       *gorm.DB
	migrator migration.IMigrator
}

// NewGormRepo returns the GORM repository (transactions in ctx are honoured).
func NewGormRepo(db *gorm.DB) ITwoFactorRepo {
	return &gormRepo{db: db, migrator: tfmodels.NewMigrator(db)}
}

func (r *gormRepo) Migrator() migration.IMigrator { return r.migrator }

func (r *gormRepo) col(field string) any {
	return gormutil.Col(r.db, &tfmodels.TwoFactor{}, field)
}

func (r *gormRepo) FindByUserID(ctx context.Context, userID string) (*tfmodels.TwoFactor, error) {
	var row tfmodels.TwoFactor
	err := gormutil.GetDB(ctx, r.db).Where("? = ?", r.col("UserID"), userID).Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func (r *gormRepo) Create(ctx context.Context, row *tfmodels.TwoFactor) error {
	// Select("*") so Verified=false is written instead of being skipped as a zero value
	return gormutil.GetDB(ctx, r.db).Select("*").Create(row).Error
}

func (r *gormRepo) DeleteByUserID(ctx context.Context, userID string) error {
	return gormutil.GetDB(ctx, r.db).Where("? = ?", r.col("UserID"), userID).Delete(&tfmodels.TwoFactor{}).Error
}

func (r *gormRepo) SetVerified(ctx context.Context, id string) error {
	return gormutil.GetDB(ctx, r.db).Model(&tfmodels.TwoFactor{}).Where("? = ?", r.col("ID"), id).Update("Verified", true).Error
}

func (r *gormRepo) UpdateBackupCodes(ctx context.Context, id, backupCodes string) error {
	return gormutil.GetDB(ctx, r.db).Model(&tfmodels.TwoFactor{}).Where("? = ?", r.col("ID"), id).Update("BackupCodes", backupCodes).Error
}

func (r *gormRepo) SwapBackupCodes(ctx context.Context, id, old, updated string) (bool, error) {
	res := gormutil.GetDB(ctx, r.db).Model(&tfmodels.TwoFactor{}).
		Where("? = ? AND ? = ?", r.col("ID"), id, r.col("BackupCodes"), old).
		Update("BackupCodes", updated)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}
