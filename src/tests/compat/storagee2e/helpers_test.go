// Package storagee2e runs goauth end to end (HTTP through a real SetupGoAuth server) on SQLite, Postgres
// and MySQL with the storage options of the schema registry: ColumnCase camel, Fields / ModelName renames,
// database-generated and serial ids, Migrations.Mode auto / verify, additionalFields migrations.
//
// Postgres and MySQL run through TEST_POSTGRES_URL / TEST_MYSQL_URL (or testcontainers) and skip without
// them.
package storagee2e

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/adapter/gormadapter/gormtest"
	"github.com/better-go-auth/goauth/src/config"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/schema"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const password = "Password123!"

// openDB returns an empty database for one test: a fresh in-memory SQLite database, a dropped and
// recreated Postgres schema named name, or (MySQL) the shared test database where the caller uses name
// as table prefix (dropTables removes leftovers).
func openDB(t *testing.T, dialect helpers.DatabaseType, name string) *gorm.DB {
	t.Helper()
	switch dialect {
	case helpers.DBTypeSQLite:
		db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:e2e_%s?mode=memory&cache=shared", uuid.NewString())), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		sqlDB, err := db.DB()
		require.NoError(t, err)
		sqlDB.SetMaxOpenConns(1)
		return db
	case helpers.DBTypePostgres:
		base := gormtest.Open(t, dialect)
		require.NoError(t, base.Exec("DROP SCHEMA IF EXISTS "+name+" CASCADE").Error)
		return gormtest.OpenIsolated(t, dialect, name)
	}
	db := gormtest.Open(t, dialect)
	dropTables(t, db, name)
	return db
}

// dropTables drops every table whose name starts with prefix (MySQL; foreign keys off meanwhile).
func dropTables(t *testing.T, db *gorm.DB, prefix string) {
	t.Helper()
	tables, err := db.Migrator().GetTables()
	require.NoError(t, err)
	require.NoError(t, db.Exec("SET FOREIGN_KEY_CHECKS = 0").Error)
	defer db.Exec("SET FOREIGN_KEY_CHECKS = 1")
	for _, tb := range tables {
		if strings.HasPrefix(tb, prefix) {
			require.NoError(t, db.Migrator().DropTable(tb))
		}
	}
}

// prefixFor returns the table prefix a test uses on MySQL (the databases of the other dialects are
// already private to the test).
func prefixFor(dialect helpers.DatabaseType, name string) string {
	if dialect == helpers.DBTypeMySQL {
		return name + "_"
	}
	return ""
}

// server starts goauth on db with cfg changes (no plugins unless given). The column case is snake unless
// cfg sets it (GOAUTH_TEST_COLUMN_CASE doesn't apply: the tests check physical names).
func server(t *testing.T, db *gorm.DB, cfg func(*config.AuthConfig), plugins ...plugin.Plugin) *compattest.Server {
	t.Helper()
	snakeFirst := func(c *config.AuthConfig) {
		c.GoAuth.ColumnCase = schema.Snake
		cfg(c)
	}
	return compattest.NewServer(t, compattest.WithDB(db), compattest.WithConfig(snakeFirst), func(o *goauth.GoAuthOptions) {
		o.Plugins = plugins
	})
}

// setup runs SetupGoAuth and returns its error (for setups that must fail).
func setup(db *gorm.DB, cfg func(*config.AuthConfig), plugins ...plugin.Plugin) (*goauth.GoAuth, error) {
	o := goauth.GoAuthOptions{Conn: db, Plugins: plugins, AuthConfig: config.AuthConfig{BaseURL: "http://127.0.0.1:8080", Secret: compattest.TestSecret}}
	cfg(&o.AuthConfig)
	return goauth.SetupGoAuth(context.Background(), humago.New(http.NewServeMux(), huma.DefaultConfig("e2e", "1")), o)
}

// sessionBody is the part of /get-session the tests read.
type sessionBody struct {
	Session struct {
		ID     string `json:"id"`
		UserID string `json:"userId"`
		Token  string `json:"token"`
	} `json:"session"`
	User struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		EmailVerified bool   `json:"emailVerified"`
	} `json:"user"`
}

// signUpInAndGetSession runs sign-up, sign-out, sign-in and get-session for email and returns the session.
func signUpInAndGetSession(t *testing.T, s *compattest.Server, email string) sessionBody {
	t.Helper()
	// Step 1: sign up (signs in)
	res := s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": email, "password": password, "name": "E2E User"})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	// Step 2: sign out, then sign in again with the password
	res = s.Post(t, "/api/auth/sign-out", map[string]any{})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	res = s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": email, "password": password})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	// Step 3: the session cookie resolves the session and user
	res = s.Get(t, "/api/auth/get-session")
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	var body sessionBody
	res.JSON(t, &body)
	require.Equal(t, email, body.User.Email)
	require.Equal(t, body.User.ID, body.Session.UserID)
	require.NotEmpty(t, body.Session.ID)
	// Step 4: a profile update goes through the same columns
	res = s.Post(t, "/api/auth/update-user", map[string]any{"name": "Renamed"})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	res = s.Get(t, "/api/auth/get-session")
	res.JSON(t, &body)
	require.Equal(t, "Renamed", body.User.Name)
	return body
}

// columnsOf returns the column names of table.
func columnsOf(t *testing.T, db *gorm.DB, table string) []string {
	t.Helper()
	cols, err := db.Migrator().ColumnTypes(table)
	require.NoError(t, err)
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = c.Name()
	}
	return out
}

// q quotes an identifier for db's dialect.
func q(db *gorm.DB, ident string) string {
	var sb strings.Builder
	db.Dialector.QuoteTo(&sb, ident)
	return sb.String()
}

// scalar reads one value with a raw query.
func scalar(t *testing.T, db *gorm.DB, query string, args ...any) any {
	t.Helper()
	var out any
	require.NoError(t, db.Raw(query, args...).Row().Scan(&out))
	if b, ok := out.([]byte); ok {
		return string(b)
	}
	return out
}

// execSQL runs generated SQL statement by statement (MySQL connections don't accept several at once), the
// way a migration tool would.
func execSQL(t *testing.T, db *gorm.DB, sql string) {
	t.Helper()
	for _, stmt := range strings.Split(sql, ";\n") {
		var lines []string
		for _, l := range strings.Split(stmt, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(l), "--") {
				lines = append(lines, l)
			}
		}
		if s := strings.TrimSpace(strings.Join(lines, "\n")); s != "" {
			require.NoError(t, db.Exec(s).Error, s)
		}
	}
}

// upper upper-cases a type name.
func upper(s string) string { return strings.ToUpper(s) }
