package sqladapter_test

import (
	"testing"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/adapter/adaptertest"
	"github.com/better-go-auth/goauth/src/adapter/sqladapter"
	"github.com/better-go-auth/goauth/src/adapter/sqladapter/sqltest"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/stretchr/testify/require"
)

// TestContract runs the adapter contract on SQLite, Postgres and MySQL (the last two skip without
// TEST_POSTGRES_URL / TEST_MYSQL_URL). Tables come from the backend's own migrator.
func TestContract(t *testing.T) {
	for _, d := range sqltest.Dialects {
		t.Run(string(d), func(t *testing.T) {
			db := sqltest.Open(t, d, "sqladapter_contract")
			adaptertest.Run(t, func(t *testing.T, reg *schema.Registry) adapter.Adapter {
				// Step 1: an empty schema per subtest
				sqltest.Reset(t, db, d, reg)
				require.NoError(t, sqltest.Migrate(db, d, reg))
				return sqladapter.NewAdapter(db, d, reg)
			}, adaptertest.Config{
				TablePrefix: "sqa_",
				// MySQL's default collations compare case-insensitively
				CaseInsensitiveEquality: d == sqladapter.MySQL,
			})
		})
	}
}
