package models

import (
	"context"
	"fmt"

	"github.com/better-go-auth/goauth/src/models/migration"
	"gorm.io/gorm"
)

type passkeyMigrator struct {
	db *gorm.DB
}

// NewMigrator returns the IMigrator creating the passkey plugin's `passkey` table.
func NewMigrator(db *gorm.DB) migration.IMigrator {
	return &passkeyMigrator{db: db}
}

// Migrate creates or updates the passkey table.
func (m *passkeyMigrator) Migrate(ctx context.Context) error {
	if m.db == nil {
		return nil
	}
	if err := m.db.WithContext(ctx).AutoMigrate(&Passkey{}); err != nil {
		return fmt.Errorf("passkey: migrate passkey table: %w", err)
	}
	return nil
}
