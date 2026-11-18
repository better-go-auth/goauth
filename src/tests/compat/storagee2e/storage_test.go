package storagee2e

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"

	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/adapter/gormadapter"
	"github.com/better-go-auth/goauth/src/adapter/gormadapter/gormtest"
	"github.com/better-go-auth/goauth/src/config"
	twofactor "github.com/better-go-auth/goauth/src/plugins/two-factor"
	tfconfig "github.com/better-go-auth/goauth/src/plugins/two-factor/config"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/better-go-auth/goauth/src/schema/render"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/stretchr/testify/require"
)

// TestCamelEndToEnd: with ColumnCase camel, sign-up / sign-in / get-session / update-user work and every
// core table uses better-auth's camelCase columns.
func TestCamelEndToEnd(t *testing.T) {
	for _, dialect := range gormtest.Dialects {
		t.Run(string(dialect), func(t *testing.T) {
			db := openDB(t, dialect, "e2e_camel")
			prefix := prefixFor(dialect, "e2e_camel")
			s := server(t, db, func(c *config.AuthConfig) {
				c.GoAuth.ColumnCase = schema.Camel
				c.GoAuth.TablePrefix = prefix
			})
			body := signUpInAndGetSession(t, s, "camel@example.com")

			// Step 1: camelCase columns, no snake_case leftovers
			require.Subset(t, columnsOf(t, db, prefix+"user"), []string{"emailVerified", "createdAt", "updatedAt", "twoFactorEnabled"})
			require.NotContains(t, columnsOf(t, db, prefix+"user"), "email_verified")
			require.Subset(t, columnsOf(t, db, prefix+"session"), []string{"userId", "expiresAt", "ipAddress", "userAgent"})
			require.Subset(t, columnsOf(t, db, prefix+"account"), []string{"accountId", "providerId", "userId", "accessTokenExpiresAt"})
			require.Subset(t, columnsOf(t, db, prefix+"verification"), []string{"identifier", "expiresAt"})

			// Step 2: the rows are where a TypeScript server would read them
			userID := scalar(t, db, fmt.Sprintf("SELECT %s FROM %s WHERE %s = ?", q(db, "userId"), q(db, prefix+"session"), q(db, "id")), body.Session.ID)
			require.Equal(t, body.User.ID, userID)
			provider := scalar(t, db, fmt.Sprintf("SELECT %s FROM %s WHERE %s = ?", q(db, "providerId"), q(db, prefix+"account"), q(db, "userId")), body.User.ID)
			require.Equal(t, "credential", provider)

			// Step 3: nothing left to migrate
			plan, _, err := goauth.PlanMigration(context.Background(), goauth.GoAuthOptions{Conn: db, AuthConfig: config.AuthConfig{GoAuth: config.GoAuthConfig{ColumnCase: schema.Camel, TablePrefix: prefix}}})
			require.NoError(t, err)
			require.True(t, plan.Empty(), "%v", plan.Summary())
		})
	}
}

// TestRenamesEndToEnd: better-auth's modelName and fields options rename core tables and columns, and every
// flow keeps working.
func TestRenamesEndToEnd(t *testing.T) {
	for _, dialect := range gormtest.Dialects {
		t.Run(string(dialect), func(t *testing.T) {
			db := openDB(t, dialect, "e2e_rename")
			prefix := prefixFor(dialect, "e2e_rename")
			cfg := func(c *config.AuthConfig) {
				c.GoAuth.TablePrefix = prefix
				c.User.ModelName = "users"
				c.User.Fields = map[string]string{"emailVerified": "is_verified", "name": "full_name"}
				c.Session.ModelName = "user_sessions"
				c.Session.Fields = map[string]string{"userId": "owner_id", "token": "session_token"}
				c.Account.Fields = map[string]string{"password": "password_hash"}
				c.Verification.ModelName = "verifications"
			}
			s := server(t, db, cfg)
			body := signUpInAndGetSession(t, s, "rename@example.com")

			// Step 1: renamed tables and columns
			require.Subset(t, columnsOf(t, db, prefix+"users"), []string{"is_verified", "full_name", "email"})
			require.NotContains(t, columnsOf(t, db, prefix+"users"), "name")
			require.Subset(t, columnsOf(t, db, prefix+"user_sessions"), []string{"owner_id", "session_token"})
			require.True(t, db.Migrator().HasTable(prefix+"verifications"))
			require.False(t, db.Migrator().HasTable(prefix+"user"), "the default table must not be created")

			// Step 2: values in the renamed columns
			require.Equal(t, "Renamed", scalar(t, db, fmt.Sprintf("SELECT %s FROM %s WHERE %s = ?", q(db, "full_name"), q(db, prefix+"users"), q(db, "id")), body.User.ID))
			require.Equal(t, body.User.ID, scalar(t, db, fmt.Sprintf("SELECT %s FROM %s WHERE %s = ?", q(db, "owner_id"), q(db, prefix+"user_sessions"), q(db, "id")), body.Session.ID))
			hash := scalar(t, db, fmt.Sprintf("SELECT %s FROM %s WHERE %s = ?", q(db, "password_hash"), q(db, prefix+"account"), q(db, "user_id")), body.User.ID)
			require.NotEmpty(t, hash)

			// Step 3: a second start migrates nothing
			s2 := server(t, db, cfg)
			res := s2.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "rename@example.com", "password": password})
			require.Equal(t, 200, res.Status, string(res.Body))
		})
	}
}

// TestSerialIDsEndToEnd: Advanced.Database.IDFormat serial (better-auth's generateId: "serial") creates
// integer ids and references, read back as strings everywhere.
func TestSerialIDsEndToEnd(t *testing.T) {
	for _, dialect := range gormtest.Dialects {
		t.Run(string(dialect), func(t *testing.T) {
			db := openDB(t, dialect, "e2e_serial")
			prefix := prefixFor(dialect, "e2e_serial")
			cfg := func(c *config.AuthConfig) {
				c.GoAuth.TablePrefix = prefix
				c.GoAuth.ColumnCase = schema.Camel
				c.Advanced.Database.IDFormat = config.IDFormatSerial
			}
			s := server(t, db, cfg)
			first := signUpInAndGetSession(t, s, "serial1@example.com")
			second := signUpInAndGetSession(t, s, "serial2@example.com")

			// Step 1: integer ids, increasing, the session references the user
			n1, err := strconv.ParseInt(first.User.ID, 10, 64)
			require.NoError(t, err, first.User.ID)
			n2, err := strconv.ParseInt(second.User.ID, 10, 64)
			require.NoError(t, err)
			require.Greater(t, n2, n1)
			_, err = strconv.ParseInt(second.Session.ID, 10, 64)
			require.NoError(t, err, second.Session.ID)
			require.Equal(t, second.User.ID, second.Session.UserID)

			// Step 2: the columns are integers
			snap, err := gormadapter.NewBackend(db).InspectTables(context.Background(), prefix+"session")
			require.NoError(t, err)
			uid, ok := snap.Tables[0].Column("userId")
			require.True(t, ok)
			require.Contains(t, []string{"BIGINT", "INTEGER", "INT8"}, upper(uid.DatabaseType))

			// Step 3: sessions are found by user id (list-sessions)
			res := s.Get(t, "/api/auth/list-sessions")
			require.Equal(t, 200, res.Status, string(res.Body))
			var sessions []map[string]any
			res.JSON(t, &sessions)
			require.NotEmpty(t, sessions)
			require.Equal(t, second.User.ID, sessions[0]["userId"])
		})
	}
}

// TestDatabaseIDsEndToEnd: IDFormat database (better-auth's generateId: false) lets the database create the
// ids (the generated DDL gives the id column a default).
func TestDatabaseIDsEndToEnd(t *testing.T) {
	for _, dialect := range gormtest.Dialects {
		t.Run(string(dialect), func(t *testing.T) {
			db := openDB(t, dialect, "e2e_dbids")
			prefix := prefixFor(dialect, "e2e_dbids")
			s := server(t, db, func(c *config.AuthConfig) {
				c.GoAuth.TablePrefix = prefix
				c.Advanced.Database.IDFormat = config.IDFormatDatabase
			})
			body := signUpInAndGetSession(t, s, "dbids@example.com")
			require.NotEmpty(t, body.User.ID)
			require.NotEqual(t, body.User.ID, body.Session.ID)
		})
	}
}

// TestDatabaseIDsRejectGORMPlugins: plugins that still store GORM structs with string ids can't run with
// database-generated ids.
func TestDatabaseIDsRejectGORMPlugins(t *testing.T) {
	db := openDB(t, helpers.DBTypeSQLite, "")
	_, err := setup(db, func(c *config.AuthConfig) { c.Advanced.Database.IDFormat = config.IDFormatSerial }, twofactor.New(tfconfig.Config{Issuer: "x"}))
	require.ErrorContains(t, err, "two-factor")
	_, err = setup(openDB(t, helpers.DBTypeSQLite, ""), func(c *config.AuthConfig) {
		c.Advanced.Database.IDFormat = config.IDFormatSerial
		c.Advanced.Database.GenerateID = func() string { return "x" }
	})
	require.ErrorContains(t, err, "GenerateID")
}

// TestVerifyModeAndGeneratedMigration is the goose / golang-migrate workflow: verify mode refuses an empty
// database and prints the SQL; the generated migration, applied by the operator, makes it start; a new
// additionalField is again reported until its migration is applied.
func TestVerifyModeAndGeneratedMigration(t *testing.T) {
	ctx := context.Background()
	for _, dialect := range gormtest.Dialects {
		t.Run(string(dialect), func(t *testing.T) {
			db := openDB(t, dialect, "e2e_verify")
			prefix := prefixFor(dialect, "e2e_verify")
			base := func(c *config.AuthConfig) {
				c.GoAuth.TablePrefix = prefix
				c.GoAuth.ColumnCase = schema.Camel
				c.GoAuth.Migrations.Mode = config.MigrationsVerify
			}
			// Step 1: an empty database fails with the missing tables and their SQL
			_, err := setup(db, base)
			var mismatch *goauth.SchemaMismatchError
			require.True(t, errors.As(err, &mismatch), "%v", err)
			require.Contains(t, err.Error(), "add table "+prefix+"user")
			require.Contains(t, err.Error(), "CREATE TABLE")
			require.False(t, db.Migrator().HasTable(prefix+"user"), "verify mode never changes the database")

			// Step 2: the operator applies the generated migration; goauth starts and works
			opts := goauth.GoAuthOptions{Conn: db}
			base(&opts.AuthConfig)
			sql, err := goauth.GenerateMigration(ctx, opts)
			require.NoError(t, err)
			execSQL(t, db, sql)
			s := server(t, db, base)
			signUpInAndGetSession(t, s, "verify@example.com")

			// Step 3: a new additionalField is missing until its migration runs
			withTier := func(c *config.AuthConfig) {
				base(c)
				c.User.AdditionalFields = map[string]schema.Field{"loyaltyTier": {Type: schema.String, Default: "bronze", Required: true}}
			}
			_, err = setup(db, withTier)
			require.ErrorContains(t, err, "add column "+prefix+"user.loyaltyTier")
			require.ErrorContains(t, err, "ALTER TABLE")
			withTierOpts := goauth.GoAuthOptions{Conn: db}
			withTier(&withTierOpts.AuthConfig)
			sql, err = goauth.GenerateMigration(ctx, withTierOpts)
			require.NoError(t, err)
			execSQL(t, db, sql)
			_, err = setup(db, withTier)
			require.NoError(t, err)
			again, err := goauth.GenerateMigration(ctx, withTierOpts)
			require.NoError(t, err)
			require.Empty(t, again, "up to date: no migration")
		})
	}
}

// TestAutoModeAddsAdditionalField: in auto mode a new additionalField becomes a column at the next start
// (existing rows get its default), a required field without default can't be added to a table with rows,
// and a restart is a no-op.
func TestAutoModeAddsAdditionalField(t *testing.T) {
	ctx := context.Background()
	for _, dialect := range gormtest.Dialects {
		t.Run(string(dialect), func(t *testing.T) {
			db := openDB(t, dialect, "e2e_auto")
			prefix := prefixFor(dialect, "e2e_auto")
			base := func(c *config.AuthConfig) { c.GoAuth.TablePrefix = prefix }
			s := server(t, db, base)
			body := signUpInAndGetSession(t, s, "auto@example.com")

			// Step 1: restart with a new field: the column appears with the default for existing rows
			withTier := func(c *config.AuthConfig) {
				base(c)
				c.User.AdditionalFields = map[string]schema.Field{"loyaltyTier": {Type: schema.String, Default: "bronze", Required: true}}
			}
			server(t, db, withTier)
			require.Contains(t, columnsOf(t, db, prefix+"user"), "loyalty_tier")
			require.Equal(t, "bronze", scalar(t, db, fmt.Sprintf("SELECT %s FROM %s WHERE %s = ?", q(db, "loyalty_tier"), q(db, prefix+"user"), q(db, "id")), body.User.ID))
			opts := goauth.GoAuthOptions{Conn: db}
			withTier(&opts.AuthConfig)
			plan, _, err := goauth.PlanMigration(ctx, opts)
			require.NoError(t, err)
			require.True(t, plan.Empty(), "second start is a no-op: %v", plan.Summary())

			// Step 2: a required field without default: setup error, nothing changed
			_, err = setup(db, func(c *config.AuthConfig) {
				withTier(c)
				c.User.AdditionalFields["taxId"] = schema.Field{Type: schema.String, Required: true}
			})
			var rce *gormadapter.RequiredColumnError
			require.True(t, errors.As(err, &rce), "%v", err)
			require.Contains(t, err.Error(), "user.taxId")
			require.NotContains(t, columnsOf(t, db, prefix+"user"), "tax_id")
		})
	}
}

// TestGeneratedSQLRunsOnEveryDialect: goauth.GenerateSQL's desired state (Atlas declarative input) for a
// camel, serial-id, rate-limited registry executes on a real database and leaves nothing to migrate.
func TestGeneratedSQLRunsOnEveryDialect(t *testing.T) {
	for _, dialect := range gormtest.Dialects {
		t.Run(string(dialect), func(t *testing.T) {
			db := openDB(t, dialect, "e2e_sql")
			prefix := prefixFor(dialect, "e2e_sql")
			opts := goauth.GoAuthOptions{Conn: db, AuthConfig: config.AuthConfig{
				GoAuth:    config.GoAuthConfig{TablePrefix: prefix, ColumnCase: schema.Camel},
				RateLimit: config.RateLimitOptions{Storage: "database"},
				Advanced:  config.Advanced{Database: config.AdvancedDatabase{IDFormat: config.IDFormatSerial}},
			}}
			d, err := render.ParseDialect(db.Dialector.Name())
			require.NoError(t, err)
			sql, err := goauth.GenerateSQL(opts, d)
			require.NoError(t, err)
			execSQL(t, db, sql)
			plan, _, err := goauth.PlanMigration(context.Background(), opts)
			require.NoError(t, err)
			require.True(t, plan.Empty(), "%v", plan.Summary())
		})
	}
}

// TestStaleGORMCacheIsReported: a connection that parsed goauth's models with another naming strategy is
// refused with an explanation instead of using two sets of table names.
func TestStaleGORMCacheIsReported(t *testing.T) {
	db := openDB(t, helpers.DBTypeSQLite, "")
	require.NoError(t, db.AutoMigrate(&appModel{}))
	_, err := setup(db, func(*config.AuthConfig) {})
	require.NoError(t, err, "unrelated models don't matter")
	_, err = setup(db, func(c *config.AuthConfig) { c.GoAuth.ColumnCase = schema.Camel })
	require.ErrorContains(t, err, "already parsed goauth's models")
}

// appModel is an application model migrated on the connection before SetupGoAuth.
type appModel struct {
	ID   string
	Note string
}
