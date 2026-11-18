package gormadapter_test

import (
	"testing"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/adapter/adaptertest"
	"github.com/better-go-auth/goauth/src/adapter/gormadapter"
	"github.com/better-go-auth/goauth/src/adapter/gormadapter/gormtest"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/stretchr/testify/require"
)

// TestContract runs the adapter contract on SQLite, Postgres and MySQL (the last two skip without Docker
// or TEST_POSTGRES_URL / TEST_MYSQL_URL). Tables are prefixed so a shared CI database can't clash with
// other packages' tables.
func TestContract(t *testing.T) {
	for _, dialect := range gormtest.Dialects {
		t.Run(string(dialect), func(t *testing.T) {
			db := gormtest.Open(t, dialect)
			adaptertest.Run(t, func(t *testing.T, reg *schema.Registry) adapter.Adapter {
				// Step 1: an empty schema per subtest
				gormtest.Reset(t, db, reg)
				require.NoError(t, gormtest.Migrate(db, reg))
				return gormadapter.New(db, reg)
			}, adaptertest.Config{
				TablePrefix: "gat_",
				// MySQL's default collations compare case-insensitively
				CaseInsensitiveEquality: dialect == helpers.DBTypeMySQL,
			})
		})
	}
}
