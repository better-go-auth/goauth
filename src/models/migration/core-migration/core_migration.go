package core_migration

import (
	"context"
	"fmt"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/migration"
	"gorm.io/gorm"
)

// GORMAdminMigrator ensures core tables have admin extensions.
type GORMMigrator struct {
	db *gorm.DB
}

// NewGORMAdminMigrator creates a new GORM migrator for admin plugin models.
func NewGORMAdminMigrator(db *gorm.DB) migration.IMigrator {
	return &GORMMigrator{db: db}
}

// Migrate executes GORM AutoMigrate for User and Session models.
func (m *GORMMigrator) Migrate(_ context.Context) error {
	err := m.db.AutoMigrate(
		&models.User{},
		&models.Session{},
		&models.Account{},
		&models.Verification{},
	)
	if err != nil {
		return fmt.Errorf("gorm/migrate-admin: %w", err)
	}
	if err := backfillUserNames(m.db); err != nil {
		return fmt.Errorf("gorm/migrate-admin: backfill user names: %w", err)
	}
	return nil
}

// backfillUserNames fills the better-auth `name` column for users created before it existed.
func backfillUserNames(db *gorm.DB) error {
	var users []models.User
	return db.Select("id", "first_name", "last_name", "name").
		Where("name = ? OR name IS NULL", "").
		FindInBatches(&users, 500, func(tx *gorm.DB, _ int) error {
			for i := range users {
				name := users[i].DisplayNameOrFull()
				if name == "" {
					continue
				}
				if err := tx.Model(&models.User{}).Where("id = ?", users[i].ID).UpdateColumn("name", name).Error; err != nil {
					return err
				}
			}
			return nil
		}).Error
}
