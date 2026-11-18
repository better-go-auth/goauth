package gormadapter_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/adapter/gormadapter"
	"github.com/better-go-auth/goauth/src/adapter/gormadapter/gormtest"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// migRegistry is a camel-case registry with a plugin table (referencing user, with a composite unique
// index), the rateLimit table, the given extra user fields and id strategy.
func migRegistry(t *testing.T, prefix string, ids schema.IDStrategy, userExtra map[string]schema.Field) *schema.Registry {
	t.Helper()
	reg, err := schema.Build(schema.Options{
		ColumnCase:  schema.Camel,
		TablePrefix: prefix,
		IDs:         ids,
		RateLimit:   true,
		Models:      map[string]schema.ModelOptions{"user": {AdditionalFields: userExtra}},
		Plugins: []schema.Plugin{{ID: "notes", Schema: schema.PluginSchema{
			"note": {Fields: map[string]schema.Field{
				"userId": {Type: schema.String, Required: true, References: &schema.Reference{Model: "user", Field: "id"}},
				"title":  {Type: schema.String, Required: true},
				"pinned": {Type: schema.Boolean, Default: false},
				"meta":   {Type: schema.JSON},
			}, Indexes: []schema.Index{{Fields: []string{"userId", "title"}, Unique: true}}},
		}}},
	})
	require.NoError(t, err)
	return reg
}

// planOf returns the plan of reg on db.
func planOf(t *testing.T, db *gorm.DB, reg *schema.Registry) *schema.Plan {
	t.Helper()
	plan, err := gormadapter.NewBackend(db).Plan(context.Background(), reg)
	require.NoError(t, err)
	return plan
}

// migrate applies the plan of reg and checks the next plan is empty (idempotence).
func migrate(t *testing.T, db *gorm.DB, reg *schema.Registry) {
	t.Helper()
	b := gormadapter.NewBackend(db)
	require.NoError(t, b.Apply(context.Background(), planOf(t, db, reg)))
	require.True(t, planOf(t, db, reg).Empty(), "second run must be a no-op: %v", planOf(t, db, reg).Summary())
}

func TestMigrator_AdditiveAndIdempotent(t *testing.T) {
	ctx := context.Background()
	for _, dialect := range gormtest.Dialects {
		t.Run(string(dialect), func(t *testing.T) {
			db := gormtest.OpenIsolated(t, dialect, "gormadapter_migrate")
			base := migRegistry(t, "mig_", schema.IDApplication, nil)
			gormtest.Reset(t, db, base)

			// Step 1: a fresh database gets every table and index, then nothing more
			plan := planOf(t, db, base)
			require.Equal(t, schema.AddTable, plan.Changes[0].Kind)
			require.Len(t, plan.Changes, len(base.Models())+countIndexes(base))
			migrate(t, db, base)

			// Step 2: the adapter works on the created tables (defaults, JSON, references, unique index)
			a := gormadapter.New(db, base)
			u, err := a.Create(ctx, "user", adapter.Record{"name": "Ada", "email": "ada@example.com"})
			require.NoError(t, err)
			n, err := a.Create(ctx, "note", adapter.Record{"userId": u["id"], "title": "t1", "meta": map[string]any{"a": 1}})
			require.NoError(t, err)
			require.Equal(t, false, n["pinned"])
			_, err = a.Create(ctx, "note", adapter.Record{"userId": u["id"], "title": "t1"})
			require.ErrorIs(t, err, adapter.ErrUniqueViolation)
			rl, err := a.Create(ctx, "rateLimit", adapter.Record{"key": "1.2.3.4|/sign-in", "count": 1})
			require.NoError(t, err)
			require.InDelta(t, time.Now().UnixMilli(), rl["lastRequest"], 60_000)

			// Step 3: a new additional field becomes a column (NOT NULL with its default) plus an index
			grown := migRegistry(t, "mig_", schema.IDApplication, map[string]schema.Field{
				"nickname": {Type: schema.String, Index: true},
				"level":    {Type: schema.Integer, Required: true, Default: 1},
			})
			plan = planOf(t, db, grown)
			require.ElementsMatch(t, []string{
				"add column mig_user.level (field user.level)",
				"add column mig_user.nickname (field user.nickname)",
				"add index idx_mig_user_nickname on mig_user (nickname)",
			}, plan.Summary())
			migrate(t, db, grown)
			snap, err := gormadapter.NewBackend(db).InspectTables(ctx, "mig_user")
			require.NoError(t, err)
			level, ok := snap.Tables[0].Column("level")
			require.True(t, ok)
			require.False(t, level.Nullable, "required field with a default is NOT NULL")
			got, err := gormadapter.New(db, grown).FindOne(ctx, "user", []adapter.Where{{Field: "id", Value: u["id"]}})
			require.NoError(t, err)
			require.Equal(t, int64(1), got["level"], "existing rows get the default")
			require.Nil(t, got["nickname"])
		})
	}
}

// countIndexes counts the indexes of every model of reg.
func countIndexes(reg *schema.Registry) int {
	n := 0
	for _, m := range reg.Models() {
		n += len(m.IndexSpecs())
	}
	return n
}

func TestMigrator_RequiredWithoutDefault(t *testing.T) {
	ctx := context.Background()
	for _, dialect := range gormtest.Dialects {
		t.Run(string(dialect), func(t *testing.T) {
			db := gormtest.OpenIsolated(t, dialect, "gormadapter_required")
			base := migRegistry(t, "req_", schema.IDApplication, nil)
			gormtest.Reset(t, db, base)
			migrate(t, db, base)
			_, err := gormadapter.New(db, base).Create(ctx, "user", adapter.Record{"name": "A", "email": "a@example.com"})
			require.NoError(t, err)

			// Step 1: a required field without a default can't be added to a table with rows
			strict := migRegistry(t, "req_", schema.IDApplication, map[string]schema.Field{"taxId": {Type: schema.String, Required: true}})
			b := gormadapter.NewBackend(db)
			err = b.Apply(ctx, planOf(t, db, strict))
			var rce *gormadapter.RequiredColumnError
			require.True(t, errors.As(err, &rce), "%v", err)
			require.Contains(t, err.Error(), "user.taxId")
			require.Contains(t, err.Error(), "ADD COLUMN")
			require.Len(t, planOf(t, db, strict).Changes, 1, "nothing was applied")

			// Step 2: on an empty table it is added (nullable: the adapter enforces required values)
			_, err = gormadapter.New(db, base).DeleteMany(ctx, "user", nil)
			require.NoError(t, err)
			migrate(t, db, strict)
			_, err = gormadapter.New(db, strict).Create(ctx, "user", adapter.Record{"name": "B", "email": "b@example.com"})
			var ve *adapter.ValueError
			require.True(t, errors.As(err, &ve), "required without a value: %v", err)
		})
	}
}

func TestMigrator_DatabaseGeneratedIDs(t *testing.T) {
	ctx := context.Background()
	for _, ids := range []schema.IDStrategy{schema.IDSerial, schema.IDDatabase} {
		for _, dialect := range gormtest.Dialects {
			t.Run(string(ids)+"/"+string(dialect), func(t *testing.T) {
				db := gormtest.OpenIsolated(t, dialect, "gormadapter_ids_"+string(ids))
				reg := migRegistry(t, "ids_", ids, nil)
				gormtest.Reset(t, db, reg)
				migrate(t, db, reg)
				a := gormadapter.New(db, reg, adapter.WithIDGenerator(func() string { panic("ids come from the database") }))

				// Step 1: users get database ids, read back through RETURNING / LAST_INSERT_ID / unique values
				u1, err := a.Create(ctx, "user", adapter.Record{"name": "One", "email": "one@example.com"})
				require.NoError(t, err)
				u2, err := a.Create(ctx, "user", adapter.Record{"name": "Two", "email": "two@example.com"})
				require.NoError(t, err)
				id1, id2 := u1["id"].(string), u2["id"].(string)
				require.NotEmpty(t, id1)
				require.NotEqual(t, id1, id2)
				if ids == schema.IDSerial {
					n1, err := strconv.ParseInt(id1, 10, 64)
					require.NoError(t, err)
					n2, err := strconv.ParseInt(id2, 10, 64)
					require.NoError(t, err)
					require.Greater(t, n2, n1)
				}

				// Step 2: references to ids (integers under serial) round-trip as strings
				s, err := a.Create(ctx, "session", adapter.Record{"userId": id2, "token": "tok-" + id2, "expiresAt": time.Now().Add(time.Hour), "updatedAt": time.Now()})
				require.NoError(t, err)
				require.Equal(t, id2, s["userId"])
				list, err := a.FindMany(ctx, "session", adapter.Query{Where: []adapter.Where{{Field: "userId", Value: id2}}})
				require.NoError(t, err)
				require.Len(t, list, 1)
				found, err := a.FindOne(ctx, "user", []adapter.Where{{Field: "id", Value: id1}})
				require.NoError(t, err)
				require.Equal(t, "one@example.com", found["email"])

				// Step 3: an id that can't exist matches nothing instead of failing
				_, err = a.FindOne(ctx, "user", []adapter.Where{{Field: "id", Value: "not-a-number"}})
				if ids == schema.IDSerial {
					require.ErrorIs(t, err, adapter.ErrNotFound)
				}
				// Step 4: an explicit id is still accepted (imports)
				if ids == schema.IDSerial && dialect != helpers.DBTypePostgres {
					u3, err := a.Create(ctx, "user", adapter.Record{"id": "1000", "name": "Three", "email": "three@example.com"})
					require.NoError(t, err)
					require.Equal(t, "1000", u3["id"])
				}
			})
		}
	}
}
