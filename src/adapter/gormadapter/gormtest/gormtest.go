// Package gormtest is test support for GORM-backed adapters: databases for each dialect (SQLite always,
// Postgres and MySQL through TEST_POSTGRES_URL / TEST_MYSQL_URL or testcontainers, skipped without Docker)
// and Migrate, which creates a registry's tables with goauth's own migrator.
package gormtest

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/adapter/gormadapter"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Dialects are the SQL dialects the contract tests run on.
var Dialects = []helpers.DatabaseType{helpers.DBTypeSQLite, helpers.DBTypePostgres, helpers.DBTypeMySQL}

// Open returns a database of the given dialect for one test (skipping when Postgres/MySQL are unavailable).
// SQLite gets one connection, so concurrent statements queue instead of failing with "table is locked".
func Open(t *testing.T, dialect helpers.DatabaseType) *gorm.DB {
	t.Helper()
	db := helpers.SetupTestDB(t, dialect)
	if dialect == helpers.DBTypeSQLite {
		sqlDB, err := db.DB()
		require.NoError(t, err)
		sqlDB.SetMaxOpenConns(1)
	}
	return db
}

// OpenIsolated is Open, but on a Postgres database shared through TEST_POSTGRES_URL / TEST_DATABASE_URL
// the connection works in its own schema (namespace), because Postgres index names are unique per schema
// and goauth's migrator uses fixed index names (idx_provider_account, ...) that other packages' tests
// create concurrently. Other dialects (and fresh test containers) need no isolation.
func OpenIsolated(t *testing.T, dialect helpers.DatabaseType, namespace string) *gorm.DB {
	t.Helper()
	db := Open(t, dialect)
	dsn := os.Getenv("TEST_POSTGRES_URL")
	if dsn == "" && strings.HasPrefix(os.Getenv("TEST_DATABASE_URL"), "postgres") {
		dsn = os.Getenv("TEST_DATABASE_URL")
	}
	if dialect != helpers.DBTypePostgres || dsn == "" {
		return db
	}
	// Step 1: the schema, created through the shared connection
	require.NoError(t, db.Exec("CREATE SCHEMA IF NOT EXISTS "+namespace).Error)
	// Step 2: a connection whose search_path is that schema
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	isolated, err := gorm.Open(postgres.Open(dsn+sep+"search_path="+namespace), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	return isolated
}

// Reset drops every table of reg (and anything referencing them).
func Reset(t *testing.T, db *gorm.DB, reg *schema.Registry) {
	t.Helper()
	models := reg.Models()
	for i := len(models) - 1; i >= 0; i-- {
		require.NoError(t, db.Migrator().DropTable(models[i].Table()))
	}
}

// Migrate creates the missing tables, columns and indexes of reg with goauth's migrator
// (gormadapter.Backend Plan + Apply, i.e. the DDL of src/schema/render).
func Migrate(db *gorm.DB, reg *schema.Registry) error {
	b := gormadapter.NewBackend(db)
	plan, err := b.Plan(context.Background(), reg)
	if err != nil {
		return err
	}
	return b.Apply(context.Background(), plan)
}
