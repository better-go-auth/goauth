package core_migration

import (
	"context"
	"fmt"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/migration"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
	// if err := PrepareLegacyColumns(m.db); err != nil {
	// 	return fmt.Errorf("gorm/migrate-admin: %w", err)
	// }
	err := m.db.AutoMigrate(
		&models.User{},
		&models.Session{},
		&models.Account{},
		&models.Verification{},
	)
	if err != nil {
		return fmt.Errorf("gorm/migrate-admin: %w", err)
	}
	// if err := caseSensitiveTokens(m.db); err != nil {
	// 	return fmt.Errorf("gorm/migrate-admin: %w", err)
	// }
	// if err := backfillUserNames(m.db); err != nil {
	// 	return fmt.Errorf("gorm/migrate-admin: backfill user names: %w", err)
	// }
	return nil
}

// caseSensitiveTokens gives session tokens a binary collation on MySQL, whose default
// collations compare case-insensitively (Postgres and SQLite already compare exactly).
func caseSensitiveTokens(db *gorm.DB) error {
	if db.Dialector.Name() != "mysql" {
		return nil
	}
	return db.Exec("ALTER TABLE ? MODIFY ? VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL",
		clause.Table{Name: models.Session{}.TableName()}, clause.Column{Name: "token"}).Error
}

// PrepareLegacyColumns renames and merges pre-better-auth columns. It must run before AutoMigrate
// (which would otherwise create the new columns empty) and is a no-op once applied.
func PrepareLegacyColumns(db *gorm.DB) error {
	m := db.Migrator()
	session := &models.Session{}
	if m.HasTable(session) {
		for _, c := range [][2]string{
			{"active_org_id", "active_organization_id"},
			{"org_role_id", "active_organization_role"},
		} {
			if m.HasColumn(session, c[0]) && !m.HasColumn(session, c[1]) {
				if err := m.RenameColumn(session, c[0], c[1]); err != nil {
					return fmt.Errorf("rename session.%s: %w", c[0], err)
				}
			}
		}
		if m.HasColumn(session, "hashed_token") {
			if !m.HasColumn(session, "token") {
				if err := m.RenameColumn(session, "hashed_token", "token"); err != nil {
					return fmt.Errorf("rename session.hashed_token: %w", err)
				}
			} else {
				if err := db.Model(session).Where("token IS NULL").UpdateColumn("token", gorm.Expr("hashed_token")).Error; err != nil {
					return fmt.Errorf("merge session.hashed_token: %w", err)
				}
				if err := m.DropColumn(session, "hashed_token"); err != nil {
					return fmt.Errorf("drop session.hashed_token: %w", err)
				}
			}
		}
	}
	// identifier used to be unique; better-auth allows duplicates
	verification := &models.Verification{}
	if m.HasTable(verification) && m.HasIndex(verification, "idx_auth_verifications_identifier") {
		if err := m.DropIndex(verification, "idx_auth_verifications_identifier"); err != nil {
			return fmt.Errorf("drop verification identifier index: %w", err)
		}
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
