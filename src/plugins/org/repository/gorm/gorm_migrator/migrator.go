package gorm_migrator

import (
	"context"
	"fmt"

	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
	"gorm.io/gorm"
)

// GORMOrgMigrator implements IMigrator for Org module models.
type GORMOrgMigrator struct {
	db *gorm.DB
}

// NewGORMOrgMigrator creates a new GORM migrator for Org module models.
func NewGORMOrgMigrator(db *gorm.DB) migration.IMigrator {
	return &GORMOrgMigrator{db: db}
}

// Migrate runs GORM AutoMigrate on Org models (Organization, Member, Invitation, OrgPermission).
func (m *GORMOrgMigrator) Migrate(_ context.Context) error {
	err := m.db.AutoMigrate(
		&models.Organization{},
		&models.Member{},
		&models.Invitation{},
		&models.OrgPermission{},
	)
	if err != nil {
		return fmt.Errorf("gorm/migrate-org: %w", err)
	}
	return nil
}
