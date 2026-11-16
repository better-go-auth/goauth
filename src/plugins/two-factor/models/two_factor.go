// Package models holds the two-factor plugin's table (better-auth's "twoFactor" model).
package models

import (
	"context"
	"fmt"

	"github.com/better-go-auth/goauth/src/models/migration"
	"gorm.io/gorm"
)

// TwoFactor is one user's 2FA secrets. The struct name maps to table "twoFactor" (gormutil naming).
// Secret is the symmetric-encrypted TOTP secret; BackupCodes is the JSON array of codes, encrypted by default.
type TwoFactor struct {
	ID          string `gorm:"primaryKey;size:255" json:"id"`
	Secret      string `gorm:"type:text;not null" json:"-"`
	BackupCodes string `gorm:"type:text;not null" json:"-"`
	UserID      string `gorm:"size:255;not null;index" json:"-"`
	// Verified is false until the first TOTP code is checked (better-auth default true for legacy rows).
	Verified bool `gorm:"not null" json:"verified"`
}

type migrator struct{ db *gorm.DB }

// NewMigrator returns the migrator creating the twoFactor table.
func NewMigrator(db *gorm.DB) migration.IMigrator { return &migrator{db: db} }

func (m *migrator) Migrate(_ context.Context) error {
	if m.db == nil {
		return nil
	}
	if err := m.db.AutoMigrate(&TwoFactor{}); err != nil {
		return fmt.Errorf("two-factor: migrate twoFactor table: %w", err)
	}
	return nil
}
