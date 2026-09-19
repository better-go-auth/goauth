package gormorg

import (
	"context"

	"github.com/better-go-auth/goauth/src/common/gormutil"
	orgrepo "github.com/better-go-auth/goauth/src/plugins/org/repository"
	"github.com/better-go-auth/goauth/src/plugins/org/repository/gorm/gorm_migrator"
	"gorm.io/gorm"
)

// getDB retrieves the active GORM transaction DB from context, or falls back to db with context.
func getDB(ctx context.Context, fallback *gorm.DB) *gorm.DB {
	return gormutil.GetDB(ctx, fallback)
}

//TODO: refactor this and make it return the interfaces not the struct

// NewOrgRepos creates a new GORM-backed OrgRepos.
func NewOrgRepos(db *gorm.DB) orgrepo.OrgRepositories {

	return orgrepo.OrgRepositories{
		IInvitationRepo: NewInvitationRepo(db),
		IMemberRepo:     NewMemberRepo(db),
		IOrgRepo:        NewOrgRepo(db),
		IMigrator:       gorm_migrator.NewGORMOrgMigrator(db),
	}
}
