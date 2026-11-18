package sqladapter_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/adapter/sqladapter"
	"github.com/better-go-auth/goauth/src/adapter/sqladapter/sqltest"
	"github.com/better-go-auth/goauth/src/app/repository/adapterrepo"
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/app/repository/repotest"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/stretchr/testify/require"
)

// TestRepositoryContract runs the core repository contract (repotest) through adapterrepo on every dialect.
func TestRepositoryContract(t *testing.T) {
	for _, d := range sqltest.Dialects {
		t.Run(string(d), func(t *testing.T) {
			db := sqltest.Open(t, d, "sqladapter_repos")
			reg := schema.MustBuild(schema.Options{TablePrefix: "sqr_", Models: repotest.ExtraFields()})
			newRepos := func(t *testing.T) repo_interfaces.IAuthRepos {
				// Step 1: fresh tables from the backend's migrator
				sqltest.Reset(t, db, d, reg)
				require.NoError(t, sqltest.Migrate(db, d, reg))
				return adapterrepo.MustNew(sqladapter.NewAdapter(db, d, reg), reg)
			}
			repotest.Run(t, newRepos)
			repotest.RunExtraFields(t, newRepos)
		})
	}
}

// TestAmbientTransaction: writes made with WithTx(ctx, appTx) commit and roll back with the application's
// own transaction, and adapter transactions inside it join it.
func TestAmbientTransaction(t *testing.T) {
	ctx := context.Background()
	for _, d := range sqltest.Dialects {
		t.Run(string(d), func(t *testing.T) {
			db := sqltest.Open(t, d, "sqladapter_tx")
			reg := schema.MustBuild(schema.Options{TablePrefix: "sqt_"})
			sqltest.Reset(t, db, d, reg)
			require.NoError(t, sqltest.Migrate(db, d, reg))
			a := sqladapter.NewAdapter(db, d, reg)
			create := func(ctx context.Context, email string) error {
				_, err := a.Create(ctx, schema.ModelUser, adapter.Record{"name": "n", "email": email})
				return err
			}
			count := func() int64 {
				n, err := a.Count(ctx, schema.ModelUser, nil)
				require.NoError(t, err)
				return n
			}
			// Step 1: the application rolls back: goauth's writes go with it
			tx, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			txCtx := sqladapter.WithTx(ctx, tx)
			require.NoError(t, create(txCtx, "a@example.com"))
			require.NoError(t, a.Transaction(txCtx, func(ctx context.Context) error {
				got, ok := sqladapter.TxFrom(ctx)
				require.True(t, ok)
				require.Same(t, tx, got, "the adapter joins the application's transaction")
				return create(ctx, "b@example.com")
			}))
			require.NoError(t, tx.Rollback())
			require.Zero(t, count())

			// Step 2: an error inside a joined transaction is returned; the owner decides
			tx, err = db.BeginTx(ctx, nil)
			require.NoError(t, err)
			txCtx = sqladapter.WithTx(ctx, tx)
			boom := errors.New("boom")
			require.ErrorIs(t, a.Transaction(txCtx, func(ctx context.Context) error {
				require.NoError(t, create(ctx, "c@example.com"))
				return boom
			}), boom)
			require.NoError(t, tx.Commit())
			require.EqualValues(t, 1, count())

			// Step 3: a panic inside the adapter's own transaction rolls back and propagates
			require.Panics(t, func() {
				_ = a.Transaction(ctx, func(ctx context.Context) error {
					require.NoError(t, create(ctx, "d@example.com"))
					panic("boom")
				})
			})
			require.EqualValues(t, 1, count())
		})
	}
}

// TestDatabaseGeneratedIDs: serial and database ids come from the database (RETURNING / LastInsertId) and
// references to serial ids are integers.
func TestDatabaseGeneratedIDs(t *testing.T) {
	ctx := context.Background()
	for _, d := range sqltest.Dialects {
		for _, ids := range []schema.IDStrategy{schema.IDSerial, schema.IDDatabase} {
			t.Run(string(d)+"/"+string(ids), func(t *testing.T) {
				db := sqltest.Open(t, d, "sqladapter_ids")
				reg := schema.MustBuild(schema.Options{TablePrefix: "sqi_", IDs: ids})
				sqltest.Reset(t, db, d, reg)
				require.NoError(t, sqltest.Migrate(db, d, reg))
				a := sqladapter.NewAdapter(db, d, reg, adapter.WithIDGenerator(func() string { panic("ids come from the database") }))
				// Step 1: two users
				u1, err := a.Create(ctx, schema.ModelUser, adapter.Record{"name": "A", "email": "a@example.com"})
				require.NoError(t, err)
				u2, err := a.Create(ctx, schema.ModelUser, adapter.Record{"name": "B", "email": "b@example.com"})
				require.NoError(t, err)
				require.NotEmpty(t, u1["id"])
				require.NotEqual(t, u1["id"], u2["id"])
				if ids == schema.IDSerial {
					require.Equal(t, "1", u1["id"])
					require.Equal(t, "2", u2["id"])
				}
				// Step 2: a session referencing the second user
				s, err := a.Create(ctx, schema.ModelSession, adapter.Record{"userId": u2["id"], "token": "t", "expiresAt": time.Now(), "updatedAt": time.Now()})
				require.NoError(t, err)
				require.Equal(t, u2["id"], s["userId"])
				n, err := a.Count(ctx, schema.ModelSession, []adapter.Where{{Field: "userId", Value: u2["id"]}})
				require.NoError(t, err)
				require.EqualValues(t, 1, n)
			})
		}
	}
}

// TestMigrator: after Apply nothing is left to plan, Inspect sees the tables, an added required field
// without a default is refused on a table with rows, and unique violations name their columns where the
// driver tells.
func TestMigrator(t *testing.T) {
	ctx := context.Background()
	for _, d := range sqltest.Dialects {
		t.Run(string(d), func(t *testing.T) {
			db := sqltest.Open(t, d, "sqladapter_migrate")
			reg := schema.MustBuild(schema.Options{TablePrefix: "sqm_"})
			sqltest.Reset(t, db, d, reg)
			b := sqladapter.New(db, d)
			// Step 1: an empty database needs every table; afterwards nothing
			plan, err := b.Plan(ctx, reg)
			require.NoError(t, err)
			require.False(t, plan.Empty())
			require.NoError(t, b.Apply(ctx, plan))
			plan, err = b.Plan(ctx, reg)
			require.NoError(t, err)
			require.True(t, plan.Empty(), "%v", plan.Summary())
			snap, err := b.Inspect(ctx)
			require.NoError(t, err)
			user, ok := snap.Table("sqm_user")
			require.True(t, ok)
			_, ok = user.Column("email")
			require.True(t, ok)
			require.True(t, user.HasIndex([]string{"email"}, true))

			// Step 2: a unique violation is an *adapter.UniqueError with the logical field when known
			a := sqladapter.NewAdapter(db, d, reg)
			_, err = a.Create(ctx, schema.ModelUser, adapter.Record{"name": "n", "email": "x@example.com"})
			require.NoError(t, err)
			_, err = a.Create(ctx, schema.ModelUser, adapter.Record{"name": "n", "email": "x@example.com"})
			var ue *adapter.UniqueError
			require.ErrorAs(t, err, &ue)
			if d != sqladapter.MySQL {
				require.Equal(t, []string{"email"}, ue.Fields)
			}

			// Step 3: a required field without a default on a table with rows is refused
			reg2 := schema.MustBuild(schema.Options{TablePrefix: "sqm_", Models: map[string]schema.ModelOptions{
				schema.ModelUser: {AdditionalFields: map[string]schema.Field{"tier": {Type: schema.String, Required: true}}},
			}})
			plan, err = b.Plan(ctx, reg2)
			require.NoError(t, err)
			var rce *adapter.RequiredColumnError
			require.ErrorAs(t, b.Apply(ctx, plan), &rce)
			require.Len(t, rce.Changes, 1)
		})
	}
}

// TestDetectDialect checks the driver-based dialect detection.
func TestDetectDialect(t *testing.T) {
	cases := map[string]sqladapter.Dialect{"sqlite3": sqladapter.SQLite, "pgx": sqladapter.Postgres, "mysql": sqladapter.MySQL}
	for driver, want := range cases {
		db, err := sql.Open(driver, "")
		require.NoError(t, err)
		got, err := sqladapter.DetectDialect(db)
		require.NoError(t, err)
		require.Equal(t, want, got, driver)
		require.Equal(t, want, mustDialect(t, sqladapter.New(db, "")))
		_ = db.Close()
	}
	require.Panics(t, func() { sqladapter.New(&sql.DB{}, "oracle") })
}

func mustDialect(t *testing.T, b *sqladapter.Backend) sqladapter.Dialect {
	d, err := b.Dialect()
	require.NoError(t, err)
	return d
}

// TestIsUniqueViolation checks the drivers' message fallbacks.
func TestIsUniqueViolation(t *testing.T) {
	for _, msg := range []string{
		`ERROR: duplicate key value violates unique constraint "idx" (SQLSTATE 23505)`,
		`Error 1062 (23000): Duplicate entry 'a' for key 'user.idx_user_email'`,
		`UNIQUE constraint failed: user.email`,
		`constraint failed: UNIQUE constraint failed: user.email (2067)`,
	} {
		require.True(t, sqladapter.IsUniqueViolation(errors.New(msg)), msg)
	}
	require.False(t, sqladapter.IsUniqueViolation(errors.New("syntax error")))
}
