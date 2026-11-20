package pluginrepotest_test

import (
	"testing"

	"github.com/better-go-auth/goauth/src/adapter/gormadapter"
	"github.com/better-go-auth/goauth/src/adapter/gormadapter/gormtest"
	"github.com/better-go-auth/goauth/src/adapter/memory"
	"github.com/better-go-auth/goauth/src/plugins/pluginrepotest"
	"github.com/better-go-auth/goauth/src/providers/idgen"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/stretchr/testify/require"
)

// TestContract_Memory runs the plugin repository contract on the memory adapter.
func TestContract_Memory(t *testing.T) {
	pluginrepotest.Run(t, func(t *testing.T) pluginrepotest.Env {
		reg := pluginrepotest.Registry(schema.Options{})
		return pluginrepotest.Env{Adapter: memory.New(reg), Schema: reg}
	})
}

// TestContract_MemorySerialIDs runs the contract with database-generated serial ids (the memory adapter
// hands out increasing integers), the way goauth runs with Advanced.Database.IDFormat "serial".
func TestContract_MemorySerialIDs(t *testing.T) {
	idgen.SetDatabaseIDs(true)
	t.Cleanup(func() { idgen.SetDatabaseIDs(false) })
	pluginrepotest.Run(t, func(t *testing.T) pluginrepotest.Env {
		reg := pluginrepotest.Registry(schema.Options{IDs: schema.IDSerial})
		return pluginrepotest.Env{Adapter: memory.New(reg), Schema: reg}
	})
}

// TestContract_GORM runs the contract through the GORM adapter on SQLite, Postgres and MySQL (the last two
// skip without Docker or TEST_POSTGRES_URL / TEST_MYSQL_URL), on tables created by goauth's migrator (with
// their foreign keys), in snake_case.
func TestContract_GORM(t *testing.T) {
	for _, dialect := range gormtest.Dialects {
		t.Run(string(dialect), func(t *testing.T) {
			runGORM(t, dialect, "pluginrepo_snake", schema.Options{TablePrefix: "prt_"})
		})
	}
}

// TestContract_GORMCamelSerial runs the contract on every dialect with better-auth's camelCase columns and
// serial ids (integer primary keys and references).
func TestContract_GORMCamelSerial(t *testing.T) {
	idgen.SetDatabaseIDs(true)
	t.Cleanup(func() { idgen.SetDatabaseIDs(false) })
	for _, dialect := range gormtest.Dialects {
		t.Run(string(dialect), func(t *testing.T) {
			runGORM(t, dialect, "pluginrepo_camel_serial", schema.Options{TablePrefix: "prs_", ColumnCase: schema.Camel, IDs: schema.IDSerial})
		})
	}
}

// runGORM runs the contract on a fresh set of tables of dialect for every subtest (on a shared Postgres
// database in its own schema namespace: index names are unique per schema).
func runGORM(t *testing.T, dialect helpers.DatabaseType, namespace string, opts schema.Options) {
	t.Helper()
	db := gormtest.OpenIsolated(t, dialect, namespace)
	reg := pluginrepotest.Registry(opts)
	pluginrepotest.Run(t, func(t *testing.T) pluginrepotest.Env {
		gormtest.Reset(t, db, reg)
		require.NoError(t, gormtest.Migrate(db, reg))
		return pluginrepotest.Env{Adapter: gormadapter.New(db, reg), Schema: reg}
	})
}
