// Package adaptere2e runs a full goauth server without GORM, through GoAuthOptions.Adapter: the
// database/sql adapter (SQLite always, Postgres / MySQL with TEST_POSTGRES_URL / TEST_MYSQL_URL) and the
// MongoDB adapter (standalone with TEST_MONGO_URL, replica set with TEST_MONGO_RS_URL).
package adaptere2e

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"testing"

	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/adapter/mongoadapter"
	"github.com/better-go-auth/goauth/src/adapter/mongoadapter/mongotest"
	"github.com/better-go-auth/goauth/src/adapter/sqladapter"
	"github.com/better-go-auth/goauth/src/adapter/sqladapter/sqltest"
	"github.com/better-go-auth/goauth/src/config"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	lastloginmethod "github.com/better-go-auth/goauth/src/plugins/last-login-method"
	llmconfig "github.com/better-go-auth/goauth/src/plugins/last-login-method/config"
	twofactor "github.com/better-go-auth/goauth/src/plugins/two-factor"
	tfconfig "github.com/better-go-auth/goauth/src/plugins/two-factor/config"
	"github.com/better-go-auth/goauth/src/schema"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
)

const password = "correct-horse-battery-staple"

// backend is one storage setup of the end-to-end test.
type backend struct {
	name string
	open func(t *testing.T) (adapter.Binder, func(t *testing.T, email string) map[string]any)
}

// backends returns the setups: sqladapter on SQLite, Postgres and MySQL, mongoadapter on both deployments. Each
// returns the binder and a raw lookup of a user row/document by email (bypassing goauth).
func backends() []backend {
	sqlBackend := func(d sqladapter.Dialect) backend {
		return backend{name: "sql-" + string(d), open: func(t *testing.T) (adapter.Binder, func(*testing.T, string) map[string]any) {
			db := sqltest.Open(t, d, "adapter_e2e")
			resetSQL(t, db, d)
			return sqladapter.New(db, d), func(t *testing.T, email string) map[string]any {
				return sqlRow(t, db, d, email)
			}
		}}
	}
	mongoBackend := func(dep mongotest.Deployment) backend {
		return backend{name: "mongo-" + string(dep), open: func(t *testing.T) (adapter.Binder, func(*testing.T, string) map[string]any) {
			db := mongotest.Open(t, dep)
			return mongoadapter.New(db), func(t *testing.T, email string) map[string]any {
				var doc bson.M
				require.NoError(t, db.Collection("user").FindOne(context.Background(), bson.D{{Key: "email", Value: email}}).Decode(&doc))
				return doc
			}
		}}
	}
	return []backend{
		sqlBackend(sqladapter.SQLite), sqlBackend(sqladapter.Postgres), sqlBackend(sqladapter.MySQL),
		mongoBackend(mongotest.Standalone), mongoBackend(mongotest.ReplicaSet),
	}
}

// resetSQL drops goauth's tables of an earlier run (the Postgres schema is shared between runs).
func resetSQL(t *testing.T, db *sql.DB, d sqladapter.Dialect) {
	t.Helper()
	for _, table := range []string{"session", "account", "verification", "user"} {
		stmt := "DROP TABLE IF EXISTS " + d.Quote(table)
		if d == sqladapter.Postgres {
			stmt += " CASCADE"
		}
		_, err := db.Exec(stmt)
		require.NoError(t, err)
	}
}

// sqlRow reads the user row with email as a map of column → value.
func sqlRow(t *testing.T, db *sql.DB, d sqladapter.Dialect, email string) map[string]any {
	t.Helper()
	ph := "?"
	if d == sqladapter.Postgres {
		ph = "$1"
	}
	rows, err := db.Query("SELECT * FROM "+d.Quote("user")+" WHERE "+d.Quote("email")+" = "+ph, email)
	require.NoError(t, err)
	defer rows.Close()
	cols, err := rows.Columns()
	require.NoError(t, err)
	require.True(t, rows.Next(), "no user %s", email)
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	require.NoError(t, rows.Scan(ptrs...))
	out := map[string]any{}
	for i, c := range cols {
		if b, ok := vals[i].([]byte); ok {
			vals[i] = string(b)
		}
		out[c] = vals[i]
	}
	return out
}

// sessionBody is the part of /get-session the test reads.
type sessionBody struct {
	Session struct {
		ID     string `json:"id"`
		UserID string `json:"userId"`
	} `json:"session"`
	User struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
	} `json:"user"`
}

// TestServerWithoutGORM: sign-up, sign-out, sign-in, get-session, update-user with an additionalField and
// the last-login-method plugin storing into the user table, on every backend through
// GoAuthOptions.Adapter, with camelCase columns (better-auth's layout).
func TestServerWithoutGORM(t *testing.T) {
	for _, b := range backends() {
		t.Run(b.name, func(t *testing.T) {
			binder, raw := b.open(t)
			s := compattest.NewServer(t, func(o *goauth.GoAuthOptions) {
				o.Conn = nil
				o.Adapter = binder
				o.GoAuth.ColumnCase = schema.Camel
				o.User.AdditionalFields = map[string]schema.Field{"favoriteColor": {Type: schema.String, Default: "blue"}}
				o.Plugins = []plugin.Plugin{lastloginmethod.New(llmconfig.LastLoginMethodConfig{StoreInDatabase: true})}
			})
			require.Nil(t, s.DB, "no GORM connection")
			const email = "adapter-e2e@example.com"

			// Step 1: sign up (signs in), sign out, sign in again with the password
			res := s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": email, "password": password, "name": "E2E User"})
			require.Equal(t, http.StatusOK, res.Status, string(res.Body))
			res = s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": email, "password": password, "name": "Again"})
			require.Equal(t, http.StatusUnprocessableEntity, res.Status, "duplicate email: %s", res.Body)
			res = s.Post(t, "/api/auth/sign-out", map[string]any{})
			require.Equal(t, http.StatusOK, res.Status, string(res.Body))
			res = s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": email, "password": "wrong-password"})
			require.Equal(t, http.StatusUnauthorized, res.Status, string(res.Body))
			res = s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": email, "password": password})
			require.Equal(t, http.StatusOK, res.Status, string(res.Body))

			// Step 2: the session cookie resolves the session and user, with the additionalField default and
			// the plugin's field
			res = s.Get(t, "/api/auth/get-session")
			require.Equal(t, http.StatusOK, res.Status, string(res.Body))
			var body sessionBody
			res.JSON(t, &body)
			require.Equal(t, email, body.User.Email)
			require.Equal(t, body.User.ID, body.Session.UserID)
			require.Equal(t, "blue", raw(t, email)["favoriteColor"], "the additionalField default is stored")

			// Step 3: update-user, then the additionalField through the repositories (the HTTP input/output of
			// additionalFields is missing-tasks 2.6)
			res = s.Post(t, "/api/auth/update-user", map[string]any{"name": "Renamed"})
			require.Equal(t, http.StatusOK, res.Status, string(res.Body))
			res = s.Get(t, "/api/auth/get-session")
			res.JSON(t, &body)
			require.Equal(t, "Renamed", body.User.Name)
			_, err := s.Auth.Repositories().UpdateUser(context.Background(), body.User.ID, map[string]any{"favoriteColor": "green"})
			require.NoError(t, err)
			u, err := s.Auth.Repositories().FindUserByID(context.Background(), body.User.ID)
			require.NoError(t, err)
			require.Equal(t, "green", u.Extra["favoriteColor"])

			// Step 4: the stored row / document uses better-auth's names
			row := raw(t, email)
			require.Equal(t, "green", row["favoriteColor"])
			require.Equal(t, "email", row["lastLoginMethod"])
			require.Contains(t, row, "emailVerified")
			if oid, ok := row["_id"].(bson.ObjectID); ok {
				require.Equal(t, body.User.ID, oid.Hex(), "MongoDB ids are ObjectIds exposed as hex")
			}

			// Step 5: list-sessions and revoke through the adapter
			res = s.Get(t, "/api/auth/list-sessions")
			require.Equal(t, http.StatusOK, res.Status, string(res.Body))
			res = s.Post(t, "/api/auth/sign-out", map[string]any{})
			require.Equal(t, http.StatusOK, res.Status, string(res.Body))
			res = s.Get(t, "/api/auth/get-session")
			require.Equal(t, "null", strings.TrimSpace(string(res.Body)))

			// Step 6: a second start on the same database migrates nothing and still works
			var plan *schema.Plan
			plan, _, err = goauth.PlanMigration(context.Background(), goauth.GoAuthOptions{Adapter: binder, AuthConfig: config.AuthConfig{
				GoAuth: config.GoAuthConfig{ColumnCase: schema.Camel},
				User:   config.UserOptions{AdditionalFields: map[string]schema.Field{"favoriteColor": {Type: schema.String, Default: "blue"}}},
			}, Plugins: []plugin.Plugin{lastloginmethod.New(llmconfig.LastLoginMethodConfig{StoreInDatabase: true})}})
			require.NoError(t, err)
			require.True(t, plan.Empty(), "%v", plan.Summary())
		})
	}
}

// TestGORMPluginIsRejected: a plugin that still needs a *gorm.DB fails setup with an error naming it.
func TestGORMPluginIsRejected(t *testing.T) {
	db := sqltest.Open(t, sqladapter.SQLite, "")
	_, err := goauth.SetupGoAuth(context.Background(), humago.New(http.NewServeMux(), huma.DefaultConfig("e2e", "1")), goauth.GoAuthOptions{
		Adapter:    sqladapter.New(db, sqladapter.SQLite),
		AuthConfig: config.AuthConfig{BaseURL: "http://127.0.0.1:8080", Secret: compattest.TestSecret},
		Plugins:    []plugin.Plugin{twofactor.New(tfconfig.Config{Issuer: "x"})},
	})
	var ge *goauth.GORMRequiredError
	require.ErrorAs(t, err, &ge)
	require.Equal(t, "two-factor", ge.Plugin)
	require.ErrorContains(t, err, "GoAuthOptions.Conn")

	// Step 2: Conn and Adapter together are refused
	_, err = goauth.SetupGoAuth(context.Background(), humago.New(http.NewServeMux(), huma.DefaultConfig("e2e", "1")), goauth.GoAuthOptions{
		Adapter: sqladapter.New(db, sqladapter.SQLite), Conn: compattest.NewServer(t).DB,
		AuthConfig: config.AuthConfig{BaseURL: "http://127.0.0.1:8080", Secret: compattest.TestSecret},
	})
	require.ErrorContains(t, err, "mutually exclusive")
}

// TestMongoVerifyMode: verify mode on an empty MongoDB database lists the missing collections and indexes;
// after a start in auto mode, verify passes.
func TestMongoVerifyMode(t *testing.T) {
	db := mongotest.Open(t, mongotest.Standalone)
	opts := func(mode config.MigrationMode) goauth.GoAuthOptions {
		o := goauth.GoAuthOptions{Adapter: mongoadapter.New(db), AuthConfig: config.AuthConfig{BaseURL: "http://127.0.0.1:8080", Secret: compattest.TestSecret}}
		o.GoAuth.Migrations.Mode = mode
		return o
	}
	setup := func(mode config.MigrationMode) error {
		_, err := goauth.SetupGoAuth(context.Background(), humago.New(http.NewServeMux(), huma.DefaultConfig("e2e", "1")), opts(mode))
		return err
	}
	// Step 1: verify on an empty database
	var mismatch *goauth.SchemaMismatchError
	require.ErrorAs(t, setup(config.MigrationsVerify), &mismatch)
	require.Contains(t, mismatch.Error(), "add table user")
	// Step 2: auto creates everything; verify passes; GenerateMigration explains it is SQL only
	require.NoError(t, setup(config.MigrationsAuto))
	require.NoError(t, setup(config.MigrationsVerify))
	_, err := goauth.GenerateMigration(context.Background(), opts(config.MigrationsAuto))
	require.ErrorContains(t, err, "SQL database")
	// Step 3: the TTL index removes expired verifications by itself (MongoDB's TTL monitor runs every 60s, so
	// only the index is checked here)
	cur, err := db.Collection("verification").Indexes().List(context.Background())
	require.NoError(t, err)
	var specs []bson.M
	require.NoError(t, cur.All(context.Background(), &specs))
	ttl := false
	for _, s := range specs {
		if _, ok := s["expireAfterSeconds"]; ok {
			ttl = true
		}
	}
	require.True(t, ttl)
}
