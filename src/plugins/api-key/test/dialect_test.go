package test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/adapter/gormadapter/gormtest"
	"github.com/better-go-auth/goauth/src/config"
	apikey "github.com/better-go-auth/goauth/src/plugins/api-key"
	apikeyconfig "github.com/better-go-auth/goauth/src/plugins/api-key/config"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// dialectDB returns an empty database of the dialect and the table prefix to use. Postgres and MySQL run
// only with TEST_POSTGRES_URL / TEST_MYSQL_URL (no testcontainers here: start your own server).
func dialectDB(t *testing.T, dialect helpers.DatabaseType, name string) (*gorm.DB, string) {
	t.Helper()
	switch dialect {
	case helpers.DBTypeSQLite:
		return gormtest.Open(t, dialect), ""
	case helpers.DBTypePostgres:
		if os.Getenv("TEST_POSTGRES_URL") == "" {
			t.Skip("TEST_POSTGRES_URL not set")
		}
		base := gormtest.Open(t, dialect)
		require.NoError(t, base.Exec("DROP SCHEMA IF EXISTS "+name+" CASCADE").Error)
		return gormtest.OpenIsolated(t, dialect, name), ""
	default:
		if os.Getenv("TEST_MYSQL_URL") == "" {
			t.Skip("TEST_MYSQL_URL not set")
		}
		db := gormtest.Open(t, dialect)
		prefix := name + "_"
		tables, err := db.Migrator().GetTables()
		require.NoError(t, err)
		require.NoError(t, db.Exec("SET FOREIGN_KEY_CHECKS = 0").Error)
		for _, tb := range tables {
			if strings.HasPrefix(tb, prefix) {
				require.NoError(t, db.Migrator().DropTable(tb))
			}
		}
		require.NoError(t, db.Exec("SET FOREIGN_KEY_CHECKS = 1").Error)
		return db, prefix
	}
}

// TestDialects runs the main flows on SQLite, Postgres and MySQL, in snake and camel column case.
func TestDialects(t *testing.T) {
	for _, dialect := range gormtest.Dialects {
		for _, cc := range []schema.ColumnCase{schema.Snake, schema.Camel} {
			t.Run(string(dialect)+"/"+string(cc), func(t *testing.T) {
				db, prefix := dialectDB(t, dialect, "apikey_e2e_"+string(cc))
				opts := []harnessOpt{
					withConfigs(apikeyconfig.Configuration{EnableMetadata: true, EnableSessionForAPIKeys: true}),
					withAuthConfig(func(c *config.AuthConfig) {
						c.GoAuth.ColumnCase = cc
						c.GoAuth.TablePrefix = prefix
					}),
				}
				opts = append(opts, withServer(func(o *goauth.GoAuthOptions) { o.Conn = db }))
				runMainFlow(t, newHarness(t, opts...))
			})
		}
	}
}

// runMainFlow exercises create, get, update, verify (remaining, refill, rate limit, permissions), the API-key
// session, list (sort, pagination), expiry cleanup and delete.
func runMainFlow(t *testing.T, h *harness) {
	t.Helper()
	ctx := context.Background()
	u := h.signUp(t)
	// Step 1: create over HTTP and read it back
	k := h.createKey(t, u, map[string]any{"name": "main", "prefix": "mk_", "metadata": map[string]any{"env": "test"}, "expiresIn": 2 * 86400})
	h.clock.Advance(time.Second)
	var got keyBody
	expectOK(t, h.Get(t, "/api/auth/api-key/get?id="+k.ID, u.as()), &got)
	require.Equal(t, "main", *got.Name)
	require.Equal(t, "test", got.Metadata.(map[string]any)["env"])
	require.Equal(t, "mk_", *got.Prefix)
	require.NotNil(t, got.ExpiresAt)
	// Step 2: update
	var upd keyBody
	expectOK(t, h.Post(t, "/api/auth/api-key/update", map[string]any{"keyId": k.ID, "name": "renamed", "metadata": map[string]any{"env": "prod"}}, u.as()), &upd)
	require.Equal(t, "renamed", *upd.Name)
	require.Equal(t, "prod", upd.Metadata.(map[string]any)["env"])
	// Step 3: usage limits on a server key
	sk, err := h.plugin.CreateAPIKey(ctx, apikey.CreateAPIKeyInput{UserID: &u.ID, Remaining: ptr[int64](1), RefillAmount: ptr[int64](2),
		RefillInterval: ptr[int64](1000), RateLimitMax: ptr[int64](100), Permissions: map[string][]string{"files": {"read"}}})
	require.NoError(t, err)
	h.clock.Advance(time.Second)
	require.True(t, h.verify(t, sk.Key, map[string][]string{"files": {"read"}}).Valid)
	expectInvalid(t, h.verify(t, sk.Key, map[string][]string{"files": {"write"}}), "KEY_NOT_FOUND", "API Key not found")
	expectInvalid(t, h.verify(t, sk.Key, nil), "USAGE_EXCEEDED", "API Key has reached its usage limit")
	h.clock.Advance(1100 * time.Millisecond)
	res := h.verify(t, sk.Key, nil)
	require.True(t, res.Valid)
	require.Equal(t, int64(1), *res.Key.Remaining)
	// Step 4: rate limit (default 10 per day): the main key's 11th use is refused
	for i := 0; i < 10; i++ {
		require.True(t, h.verify(t, k.Key, nil).Valid, "use %d", i)
	}
	rl := h.verify(t, k.Key, nil)
	require.Equal(t, "RATE_LIMITED", rl.Error.Code)
	// Step 5: the session of a fresh key
	sess := h.createKey(t, u, nil)
	var s sessionBody
	expectOK(t, h.Get(t, "/api/auth/get-session", keyHeader(sess.Key)), &s)
	require.Equal(t, u.ID, s.User.ID)
	// Step 6: list sorted and paginated
	var list struct {
		APIKeys []keyBody `json:"apiKeys"`
		Total   int       `json:"total"`
	}
	expectOK(t, h.Get(t, "/api/auth/api-key/list?sortBy=createdAt&sortDirection=asc&limit=2", u.as()), &list)
	require.Equal(t, 3, list.Total)
	require.Len(t, list.APIKeys, 2)
	require.Equal(t, k.ID, list.APIKeys[0].ID)
	// Step 7: expiry cleanup and delete
	h.clock.Advance(3 * 86400 * time.Second)
	require.NoError(t, h.plugin.DeleteAllExpiredAPIKeys(ctx))
	expectError(t, h.Get(t, "/api/auth/api-key/get?id="+k.ID, u.as()), 404, "KEY_NOT_FOUND")
	expectOK(t, h.Post(t, "/api/auth/api-key/delete", map[string]any{"keyId": sess.ID}, u.as()), nil)
	expectOK(t, h.Get(t, "/api/auth/api-key/list", u.as()), &list)
	require.Equal(t, 1, list.Total)
	require.Equal(t, sk.ID, list.APIKeys[0].ID)
}
