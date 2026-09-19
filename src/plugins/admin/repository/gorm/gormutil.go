package gormadmin

import (
	"context"

	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/plugins/admin/repository"
	"github.com/better-go-auth/goauth/src/plugins/admin/repository/gorm/gorm_migrator"
	"gorm.io/gorm"
)

func getDB(ctx context.Context, fallback *gorm.DB) *gorm.DB {
	return gormutil.GetDB(ctx, fallback)
}

// NewAdminGormRepos creates a new GORM-backed AdminRepositories bundle.
func NewAdminGormRepos(db *gorm.DB) repository.AdminRepositories {
	return repository.AdminRepositories{
		AdminRepo: NewAdminRepo(db),
		Migrator:  gorm_migrator.NewGORMAdminMigrator(db),
	}
}
