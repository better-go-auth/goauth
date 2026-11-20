// Package sqltest is test support for the database/sql adapter: a *sql.DB per dialect (SQLite always,
// through mattn/go-sqlite3; Postgres through pgx's stdlib and TEST_POSTGRES_URL; MySQL through
// go-sql-driver/mysql and TEST_MYSQL_URL; the last two skip without their variable), and Migrate / Reset for
// a registry's tables.
package sqltest

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/adapter/sqladapter"
	"github.com/better-go-auth/goauth/src/schema"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
)

// Dialects are the dialects the tests run on.
var Dialects = []sqladapter.Dialect{sqladapter.SQLite, sqladapter.Postgres, sqladapter.MySQL}

// Open returns a database of dialect d for one test, closed on cleanup. Postgres connections work in their
// own schema named namespace (index names are unique per schema, and other packages' tests share the
// database). SQLite is a file with one connection, so concurrent statements queue instead of failing.
func Open(t *testing.T, d sqladapter.Dialect, namespace string) *sql.DB {
	t.Helper()
	switch d {
	case sqladapter.Postgres:
		return openPostgres(t, namespace)
	case sqladapter.MySQL:
		dsn := os.Getenv("TEST_MYSQL_URL")
		if dsn == "" {
			t.Skip("TEST_MYSQL_URL not set")
		}
		db, err := sql.Open("mysql", strings.TrimPrefix(dsn, "mysql://"))
		require.NoError(t, err)
		t.Cleanup(func() { _ = db.Close() })
		require.NoError(t, db.Ping())
		return db
	}
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "test.db")+"?_foreign_keys=1&_busy_timeout=5000")
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// openPostgres connects to TEST_POSTGRES_URL with search_path = namespace (created when missing).
func openPostgres(t *testing.T, namespace string) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_URL not set")
	}
	// Step 1: the schema, through a plain connection
	admin, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	_, err = admin.Exec(fmt.Sprintf(`CREATE SCHEMA IF NOT EXISTS %q`, namespace))
	_ = admin.Close()
	require.NoError(t, err)
	// Step 2: a connection whose search_path is that schema
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	q := u.Query()
	q.Set("search_path", namespace)
	u.RawQuery = q.Encode()
	db, err := sql.Open("pgx", u.String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// Reset drops every table of reg (dependent tables first).
func Reset(t *testing.T, db *sql.DB, d sqladapter.Dialect, reg *schema.Registry) {
	t.Helper()
	models := schema.DependencyOrder(reg)
	for i := len(models) - 1; i >= 0; i-- {
		stmt := "DROP TABLE IF EXISTS " + d.Quote(models[i].Table())
		if d == sqladapter.Postgres {
			stmt += " CASCADE"
		}
		_, err := db.Exec(stmt)
		require.NoError(t, err)
	}
}

// Migrate creates the missing tables, columns and indexes of reg with the backend's migrator.
func Migrate(db *sql.DB, d sqladapter.Dialect, reg *schema.Registry) error {
	b := sqladapter.New(db, d)
	plan, err := b.Plan(context.Background(), reg)
	if err != nil {
		return err
	}
	return b.Apply(context.Background(), plan)
}
