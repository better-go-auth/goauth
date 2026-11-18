package gormauth_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/app/repository/gormauth"
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/app/repository/repotest"
	"github.com/better-go-auth/goauth/src/models"
	coremigrator "github.com/better-go-auth/goauth/src/models/migration/core-migration"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestContract_Postgres runs the repository contract against a real Postgres database.
// It only runs when TEST_POSTGRES_URL is set (CI sets it through the database matrix).
func TestContract_Postgres(t *testing.T) {
	dsn := os.Getenv("TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_URL not set")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	runContractOn(t, db)
}

// TestContract_MySQL runs the repository contract against a real MySQL database.
// It only runs when TEST_MYSQL_URL is set (CI sets it through the database matrix).
func TestContract_MySQL(t *testing.T) {
	dsn := os.Getenv("TEST_MYSQL_URL")
	if dsn == "" {
		t.Skip("TEST_MYSQL_URL not set")
	}
	// Step 1: MySQL needs parseTime so DATETIME columns scan into time.Time
	if !strings.Contains(dsn, "parseTime=") {
		if strings.Contains(dsn, "?") {
			dsn += "&parseTime=true"
		} else {
			dsn += "?parseTime=true"
		}
	}
	db, err := gorm.Open(mysql.New(mysql.Config{DSN: dsn, DefaultStringSize: 256}), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	runContractOn(t, db)
}

// runContractOn gives every contract subtest an empty schema built by the real core migrator,
// so the indexes and column types are the ones production databases get.
func runContractOn(t *testing.T, db *gorm.DB) {
	repotest.Run(t, func(t *testing.T) repo_interfaces.IAuthRepos {
		// Step 1: drop the core tables left by the previous subtest
		require.NoError(t, db.Migrator().DropTable(&models.Verification{}, &models.Account{}, &models.Session{}, &models.User{}))
		// Step 2: recreate them with the production migrator
		require.NoError(t, coremigrator.NewGORMAdminMigrator(db).Migrate(context.Background()))
		return gormauth.NewAuthRepos(db)
	})
}
