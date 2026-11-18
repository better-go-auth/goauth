// Package gormtest is test support for GORM-backed adapters: databases for each dialect (SQLite always,
// Postgres and MySQL through TEST_POSTGRES_URL / TEST_MYSQL_URL or testcontainers, skipped without Docker)
// and a minimal DDL builder that creates the tables and columns of a registry.
//
// The DDL here only exists so the contract tests can run on any registry; it is not goauth's migrator
// (task 2.7 builds that, with per-dialect type rendering and index handling).
package gormtest

import (
	"context"
	"fmt"
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

// Migrate creates the missing tables and columns of reg (unique constraints included).
func Migrate(db *gorm.DB, reg *schema.Registry) error {
	// Step 1: what is missing
	var tables []string
	for _, m := range reg.Models() {
		tables = append(tables, m.Table())
	}
	snap, err := gormadapter.NewBackend(db).InspectTables(context.Background(), tables...)
	if err != nil {
		return err
	}
	plan := schema.Diff(reg, snap)
	dialect := db.Dialector.Name()
	q := func(name string) string {
		var sb strings.Builder
		db.Dialector.QuoteTo(&sb, name)
		return sb.String()
	}
	// Step 2: one statement per missing table / column, then the unique indexes of new tables
	for _, c := range plan.Changes {
		m, _ := reg.Model(c.Model)
		// fields of multi-column indexes need an indexable type (MySQL can't index TEXT)
		indexed := map[string]bool{}
		for _, idx := range m.Indexes() {
			for _, fn := range idx.Fields {
				indexed[fn] = true
			}
		}
		switch c.Kind {
		case schema.AddTable:
			var cols []string
			for _, f := range m.Fields() {
				cols = append(cols, q(f.Column)+" "+columnDef(dialect, f, true, indexed[f.Name]))
			}
			if err := db.Exec(fmt.Sprintf("CREATE TABLE %s (%s)", q(m.Table()), strings.Join(cols, ", "))).Error; err != nil {
				return fmt.Errorf("create %s: %w", m.Table(), err)
			}
			for i, idx := range m.Indexes() {
				if !idx.Unique {
					continue
				}
				var cols []string
				for _, fn := range idx.Fields {
					cols = append(cols, q(m.Column(fn)))
				}
				name := fmt.Sprintf("uidx_%s_%d", m.Table(), i)
				if err := db.Exec(fmt.Sprintf("CREATE UNIQUE INDEX %s ON %s (%s)", q(name), q(m.Table()), strings.Join(cols, ", "))).Error; err != nil {
					return fmt.Errorf("index %s: %w", name, err)
				}
			}
		case schema.AddColumn:
			if err := db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", q(c.Table), q(c.Field.Column), columnDef(dialect, c.Field, false, indexed[c.Field.Name]))).Error; err != nil {
				return fmt.Errorf("add %s.%s: %w", c.Table, c.Field.Column, err)
			}
			if c.Field.Unique {
				name := fmt.Sprintf("uidx_%s_%s", c.Table, c.Field.Column)
				if err := db.Exec(fmt.Sprintf("CREATE UNIQUE INDEX %s ON %s (%s)", q(name), q(c.Table), q(c.Field.Column))).Error; err != nil {
					return fmt.Errorf("index %s: %w", name, err)
				}
			}
		}
	}
	return nil
}

// columnDef renders a column type (and constraints for new tables) for dialect.
func columnDef(dialect string, f schema.ResolvedField, newTable, indexed bool) string {
	def := columnType(dialect, f, indexed)
	if f.Name == "id" {
		return def + " PRIMARY KEY"
	}
	if newTable && f.Required {
		def += " NOT NULL"
	}
	if newTable && f.Unique {
		def += " UNIQUE"
	}
	return def
}

// columnType maps a logical type to a physical one (plan 02 §4.5's table).
func columnType(dialect string, f schema.ResolvedField, indexed bool) string {
	keyed := indexed || f.Unique || f.Index || f.Sortable || f.References != nil || f.Type == schema.ID
	switch dialect {
	case "postgres":
		switch f.Type {
		case schema.Number:
			return "double precision"
		case schema.Integer:
			return "bigint"
		case schema.Boolean:
			return "boolean"
		case schema.Date:
			return "timestamptz"
		case schema.JSON, schema.StringArray, schema.NumberArray:
			return "jsonb"
		}
		if keyed {
			return "varchar(255)"
		}
		return "text"
	case "mysql":
		switch f.Type {
		case schema.Number:
			return "double"
		case schema.Integer:
			return "bigint"
		case schema.Boolean:
			return "tinyint(1)"
		case schema.Date:
			return "datetime(3)"
		case schema.JSON, schema.StringArray, schema.NumberArray:
			return "json"
		}
		if keyed {
			return "varchar(255)"
		}
		return "text"
	}
	switch f.Type {
	case schema.Number:
		return "real"
	case schema.Integer:
		return "integer"
	case schema.Boolean:
		return "numeric"
	case schema.Date:
		return "datetime"
	}
	return "text"
}
