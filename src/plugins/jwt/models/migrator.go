package models

import (
	"context"
	"fmt"

	"github.com/better-go-auth/goauth/src/models/migration"
	"gorm.io/gorm"
)

type jwksMigrator struct {
	db *gorm.DB
}

// NewMigrator returns a new IMigrator for the JWT plugin's jwks table.
func NewMigrator(db *gorm.DB) migration.IMigrator {
	return &jwksMigrator{db: db}
}

func (m *jwksMigrator) Migrate(_ context.Context) error {
	if m.db == nil {
		return nil
	}
	if err := m.db.AutoMigrate(&JWK{}); err != nil {
		return fmt.Errorf("jwt: migrate jwks table: %w", err)
	}
	return nil
}
