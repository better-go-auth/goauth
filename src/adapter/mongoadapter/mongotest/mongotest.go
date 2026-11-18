// Package mongotest is test support for the MongoDB adapter: a fresh database per test on a standalone
// server (TEST_MONGO_URL) or a replica set (TEST_MONGO_RS_URL, for transactions), skipped when the variable
// is not set, and Migrate for a registry's collections and indexes.
package mongotest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/adapter/mongoadapter"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Deployment is a kind of MongoDB server.
type Deployment string

const (
	// Standalone is a single server without transactions (TEST_MONGO_URL).
	Standalone Deployment = "standalone"
	// ReplicaSet is a (single-node) replica set with transactions (TEST_MONGO_RS_URL).
	ReplicaSet Deployment = "replset"
)

// Deployments are the deployments the tests run on.
var Deployments = []Deployment{Standalone, ReplicaSet}

// envVar returns the variable holding the URL of a deployment.
func envVar(d Deployment) string {
	if d == ReplicaSet {
		return "TEST_MONGO_RS_URL"
	}
	return "TEST_MONGO_URL"
}

// Open returns a new, empty database on deployment d (dropped on cleanup), or skips the test when the
// deployment's URL variable is not set.
func Open(t *testing.T, d Deployment) *mongo.Database {
	t.Helper()
	uri := os.Getenv(envVar(d))
	if uri == "" {
		t.Skip(envVar(d) + " not set")
	}
	client, err := mongo.Connect(options.Client().ApplyURI(uri).SetTimeout(30 * time.Second))
	require.NoError(t, err)
	var buf [6]byte
	_, _ = rand.Read(buf[:])
	db := client.Database("goauth_test_" + hex.EncodeToString(buf[:]))
	t.Cleanup(func() {
		ctx := context.Background()
		_ = db.Drop(ctx)
		_ = client.Disconnect(ctx)
	})
	return db
}

// Migrate creates the collections and indexes of reg with the adapter's migrator.
func Migrate(db *mongo.Database, reg *schema.Registry, opts ...mongoadapter.Option) error {
	b := mongoadapter.New(db, opts...)
	plan, err := b.Plan(context.Background(), reg)
	if err != nil {
		return err
	}
	return b.Apply(context.Background(), plan)
}
