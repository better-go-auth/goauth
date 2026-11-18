package mongoadapter_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/adapter/adaptertest"
	"github.com/better-go-auth/goauth/src/adapter/mongoadapter"
	"github.com/better-go-auth/goauth/src/adapter/mongoadapter/mongotest"
	"github.com/better-go-auth/goauth/src/app/repository/adapterrepo"
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/app/repository/repotest"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// newAdapter returns an adapter for reg on a fresh database of deployment d with the registry's
// collections and indexes.
func newAdapter(t *testing.T, d mongotest.Deployment, reg *schema.Registry, opts ...mongoadapter.Option) (adapter.Adapter, *mongo.Database) {
	t.Helper()
	db := mongotest.Open(t, d)
	require.NoError(t, mongotest.Migrate(db, reg, opts...))
	a, err := mongoadapter.NewAdapter(db, reg, opts...)
	require.NoError(t, err)
	return a, db
}

// TestContract runs the adapter contract on a standalone server (transactions not atomic) and on a replica
// set (atomic transactions); each skips without TEST_MONGO_URL / TEST_MONGO_RS_URL.
func TestContract(t *testing.T) {
	for _, d := range mongotest.Deployments {
		t.Run(string(d), func(t *testing.T) {
			adaptertest.Run(t, func(t *testing.T, reg *schema.Registry) adapter.Adapter {
				a, _ := newAdapter(t, d, reg)
				return a
			}, adaptertest.Config{
				IDLength:              24,
				NonAtomicTransactions: d == mongotest.Standalone,
			})
		})
	}
}

// TestRepositoryContract runs the core repository contract through adapterrepo.
func TestRepositoryContract(t *testing.T) {
	for _, d := range mongotest.Deployments {
		t.Run(string(d), func(t *testing.T) {
			reg := schema.MustBuild(schema.Options{Models: repotest.ExtraFields()})
			newRepos := func(t *testing.T) repo_interfaces.IAuthRepos {
				a, _ := newAdapter(t, d, reg)
				return adapterrepo.MustNew(a, reg)
			}
			repotest.Run(t, newRepos)
			repotest.RunExtraFields(t, newRepos)
		})
	}
}

// TestNullableUniqueAndTTL: users without a phone number or username don't conflict (partial unique
// indexes), duplicates still do, and verification / session have TTL indexes on expiresAt.
func TestNullableUniqueAndTTL(t *testing.T) {
	ctx := context.Background()
	reg := schema.MustBuild(schema.Options{})
	a, db := newAdapter(t, mongotest.Standalone, reg)
	// Step 1: two users without phone numbers / usernames
	for _, email := range []string{"a@example.com", "b@example.com"} {
		_, err := a.Create(ctx, schema.ModelUser, adapter.Record{"name": "n", "email": email})
		require.NoError(t, err)
	}
	_, err := a.Create(ctx, schema.ModelUser, adapter.Record{"name": "n", "email": "c@example.com", "phoneNumber": nil})
	require.NoError(t, err, "an explicit null doesn't conflict either")
	// Step 2: a duplicate phone number does, and names its field
	_, err = a.Create(ctx, schema.ModelUser, adapter.Record{"name": "n", "email": "d@example.com", "phoneNumber": "+1555"})
	require.NoError(t, err)
	_, err = a.Create(ctx, schema.ModelUser, adapter.Record{"name": "n", "email": "e@example.com", "phoneNumber": "+1555"})
	var ue *adapter.UniqueError
	require.ErrorAs(t, err, &ue)
	require.Equal(t, []string{"phoneNumber"}, ue.Fields)
	// Step 3: TTL indexes
	for _, coll := range []string{"verification", "session"} {
		cur, err := db.Collection(coll).Indexes().List(ctx)
		require.NoError(t, err)
		var specs []bson.M
		require.NoError(t, cur.All(ctx, &specs))
		found := false
		for _, s := range specs {
			if key, ok := s["key"].(bson.D); ok && len(key) == 1 && key[0].Key == "expiresAt" {
				require.EqualValues(t, 0, s["expireAfterSeconds"], coll)
				found = true
			}
		}
		require.True(t, found, "TTL index on %s.expiresAt", coll)
	}
	// Step 4: a second migration has nothing to do; Inspect sees the indexes
	b := mongoadapter.New(db)
	plan, err := b.Plan(ctx, reg)
	require.NoError(t, err)
	require.True(t, plan.Empty(), "%v", plan.Summary())
	snap, err := b.Inspect(ctx)
	require.NoError(t, err)
	user, ok := snap.Table("user")
	require.True(t, ok)
	require.True(t, user.HasIndex([]string{"email"}, true))
}

// TestObjectIDs: ids are ObjectIds in the database and hex strings in records; references to ids are
// ObjectIds too; ids that aren't ObjectId hex strings stay strings; WithStringIDs stores strings.
func TestObjectIDs(t *testing.T) {
	ctx := context.Background()
	reg := schema.MustBuild(schema.Options{ColumnCase: schema.Snake})
	a, db := newAdapter(t, mongotest.Standalone, reg)
	// Step 1: a user and a session referencing it
	u, err := a.Create(ctx, schema.ModelUser, adapter.Record{"name": "n", "email": "o@example.com"})
	require.NoError(t, err)
	id := u["id"].(string)
	oid, err := bson.ObjectIDFromHex(id)
	require.NoError(t, err)
	_, err = a.Create(ctx, schema.ModelSession, adapter.Record{"userId": id, "token": "tok", "expiresAt": time.Now().Add(time.Hour), "updatedAt": time.Now()})
	require.NoError(t, err)
	// Step 2: the raw documents use ObjectIds and camelCase keys despite snake case columns
	var raw bson.M
	require.NoError(t, db.Collection("user").FindOne(ctx, bson.D{{Key: "_id", Value: oid}}).Decode(&raw))
	require.Equal(t, false, raw["emailVerified"])
	require.NotContains(t, raw, "email_verified")
	require.NoError(t, db.Collection("session").FindOne(ctx, bson.D{{Key: "token", Value: "tok"}}).Decode(&raw))
	require.Equal(t, oid, raw["userId"])
	// Step 3: lookups by hex id and by reference
	got, err := a.FindOne(ctx, schema.ModelSession, []adapter.Where{{Field: "userId", Value: id}})
	require.NoError(t, err)
	require.Equal(t, id, got["userId"])
	n, err := a.Count(ctx, schema.ModelUser, []adapter.Where{{Field: "id", Op: adapter.In, Value: []string{id, "not-an-object-id"}}})
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	// Step 4: other ids are strings
	custom, err := a.Create(ctx, schema.ModelUser, adapter.Record{"id": "custom-id", "name": "n", "email": "c@example.com"})
	require.NoError(t, err)
	require.Equal(t, "custom-id", custom["id"])
	require.NoError(t, db.Collection("user").FindOne(ctx, bson.D{{Key: "_id", Value: "custom-id"}}).Decode(&raw))

	// Step 5: WithStringIDs
	sa, sdb := newAdapter(t, mongotest.Standalone, reg, mongoadapter.WithStringIDs())
	su, err := sa.Create(ctx, schema.ModelUser, adapter.Record{"name": "n", "email": "s@example.com"})
	require.NoError(t, err)
	require.Len(t, su["id"], 32, "the factory's default generator")
	require.NoError(t, sdb.Collection("user").FindOne(ctx, bson.D{{Key: "_id", Value: su["id"]}}).Decode(&raw))
}

// TestIDStrategies: the database id strategy lets MongoDB create ObjectIds; serial is refused.
func TestIDStrategies(t *testing.T) {
	ctx := context.Background()
	reg := schema.MustBuild(schema.Options{IDs: schema.IDDatabase})
	a, _ := newAdapter(t, mongotest.Standalone, reg)
	u, err := a.Create(ctx, schema.ModelUser, adapter.Record{"name": "n", "email": "db@example.com"})
	require.NoError(t, err)
	_, err = bson.ObjectIDFromHex(u["id"].(string))
	require.NoError(t, err)

	_, err = mongoadapter.New(nil).Bind(schema.MustBuild(schema.Options{IDs: schema.IDSerial}))
	require.Error(t, err)
}

// TestTransactionSupport: a replica set reports transactions, a standalone server doesn't; an
// application session in ctx is joined.
func TestTransactionSupport(t *testing.T) {
	ctx := context.Background()
	reg := schema.MustBuild(schema.Options{})
	for _, d := range mongotest.Deployments {
		t.Run(string(d), func(t *testing.T) {
			db := mongotest.Open(t, d)
			require.NoError(t, mongotest.Migrate(db, reg))
			b := mongoadapter.New(db)
			require.Equal(t, d == mongotest.ReplicaSet, b.SupportsTransactions(ctx))
			if d != mongotest.ReplicaSet {
				return
			}
			a, err := b.Bind(reg)
			require.NoError(t, err)
			// Step 1: the application's own transaction: goauth's writes go with its abort
			sess, err := db.Client().StartSession()
			require.NoError(t, err)
			defer sess.EndSession(ctx)
			require.NoError(t, sess.StartTransaction())
			sctx := mongo.NewSessionContext(ctx, sess)
			boom := errors.New("boom")
			require.ErrorIs(t, a.Transaction(sctx, func(ctx context.Context) error {
				_, err := a.Create(ctx, schema.ModelUser, adapter.Record{"name": "n", "email": "tx@example.com"})
				require.NoError(t, err)
				return boom
			}), boom)
			require.NoError(t, sess.AbortTransaction(ctx))
			n, err := a.Count(ctx, schema.ModelUser, nil)
			require.NoError(t, err)
			require.Zero(t, n)
		})
	}
}
