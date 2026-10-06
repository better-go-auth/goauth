package gormauth_test

import (
	"fmt"
	"testing"

	"github.com/better-go-auth/goauth/src/app/repository/gormauth"
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/app/repository/repotest"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestContract(t *testing.T) {
	repotest.Run(t, func(t *testing.T) repo_interfaces.IAuthRepos {
		dsn := fmt.Sprintf("file:contract_%s?mode=memory&cache=shared", uuid.NewString())
		db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}, &models.Account{}, &models.Verification{}))
		return gormauth.NewAuthRepos(db)
	})
}
