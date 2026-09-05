package gormadmin

import (
	"context"

	"github.com/better-go-auth/goauth/src/plugins/admin/repository"
	"github.com/better-go-auth/goauth/src/plugins/admin/repository/gorm/gorm_migrator"
	"gorm.io/gorm"
)

type ContextKey string

const TxKey ContextKey = "gorm_admin_tx"

func getDB(ctx context.Context, fallback *gorm.DB) *gorm.DB {
	if tx, ok := ctx.Value(TxKey).(*gorm.DB); ok {
		return tx.WithContext(ctx)
	}
	return fallback.WithContext(ctx)
}

// NewAdminRepos creates a new GORM-backed AdminRepositories bundle.
func NewAdminRepos(db *gorm.DB) repository.AdminRepositories {
	return repository.AdminRepositories{
		AdminRepo: NewAdminRepo(db),
		Migrator:  gorm_migrator.NewGORMAdminMigrator(db),
	}
}
