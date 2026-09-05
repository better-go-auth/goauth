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
	return nil
}
