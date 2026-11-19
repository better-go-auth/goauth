package storagee2e

import (
	"context"
	"net/http"
	"testing"

	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/adapter/gormadapter/gormtest"
	"github.com/better-go-auth/goauth/src/config"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/admin"
	"github.com/better-go-auth/goauth/src/plugins/anonymous"
	anonconfig "github.com/better-go-auth/goauth/src/plugins/anonymous/config"
	phonenumber "github.com/better-go-auth/goauth/src/plugins/phone-number"
	phoneconfig "github.com/better-go-auth/goauth/src/plugins/phone-number/config"
	twofactor "github.com/better-go-auth/goauth/src/plugins/two-factor"
	tfconfig "github.com/better-go-auth/goauth/src/plugins/two-factor/config"
	"github.com/better-go-auth/goauth/src/plugins/username"
	usernameconfig "github.com/better-go-auth/goauth/src/plugins/username/config"
	"github.com/better-go-auth/goauth/src/schema"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// pluginUserColumns are the user columns of admin, phone-number, two-factor, username and anonymous.
var pluginUserColumns = []string{"role", "banned", "ban_reason", "ban_expires", "phone_number", "phone_number_verified",
	"two_factor_enabled", "username", "display_username", "is_anonymous"}

// userJSON signs up email and returns the user object of /get-session.
func userJSON(t *testing.T, s *compattest.Server, email string) map[string]any {
	t.Helper()
	res := s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": email, "password": password, "name": "P"})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	res = s.Get(t, "/api/auth/get-session")
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	var body map[string]map[string]any
	res.JSON(t, &body)
	return body["user"]
}

// TestPluginColumnsOnlyForInstalledPlugins (missing-tasks 2.8, blocker B10): without plugins goauth creates
// none of their columns and the user JSON has none of their fields; with them every column exists and
// the JSON always carries their fields (false / null when unset); columns of an uninstalled plugin that
// already exist are kept and ignored.
func TestPluginColumnsOnlyForInstalledPlugins(t *testing.T) {
	for _, dialect := range gormtest.Dialects {
		t.Run(string(dialect), func(t *testing.T) {
			db := openDB(t, dialect, "e2e_plugcols")
			prefix := prefixFor(dialect, "e2e_plugcols")
			cfg := func(c *config.AuthConfig) { c.GoAuth.TablePrefix = prefix }

			// Step 1: no plugins: no plugin columns, no plugin fields in the JSON
			s := server(t, db, cfg)
			cols := columnsOf(t, db, prefix+"user")
			for _, c := range pluginUserColumns {
				require.NotContains(t, cols, c)
			}
			require.NotContains(t, columnsOf(t, db, prefix+"session"), "impersonated_by")
			user := userJSON(t, s, "plain@example.com")
			for _, k := range []string{"role", "banned", "phoneNumber", "twoFactorEnabled", "username", "isAnonymous"} {
				require.NotContains(t, user, k)
			}

			// Step 2: the same database with the plugins: columns added, fields always present
			adminPlugin, err := admin.NewWithGorm(db)
			require.NoError(t, err)
			plugins := []plugin.Plugin{
				adminPlugin,
				phonenumber.New(phoneconfig.PhoneNumberConfig{SendOTP: func(phoneconfig.OTPData, *http.Request) error { return nil }}),
				twofactor.New(tfconfig.Config{Issuer: "e2e"}),
				username.New(usernameconfig.UsernameConfig{}),
				anonymous.New(anonconfig.AnonymousConfig{}),
			}
			s = server(t, openSameDB(t, db), cfg, plugins...)
			cols = columnsOf(t, db, prefix+"user")
			require.Subset(t, cols, pluginUserColumns)
			require.Contains(t, columnsOf(t, db, prefix+"session"), "impersonated_by")
			user = userJSON(t, s, "full@example.com")
			require.Equal(t, "user", user["role"])
			for k, want := range map[string]any{"banned": false, "twoFactorEnabled": false, "isAnonymous": false,
				"banReason": nil, "banExpires": nil, "phoneNumber": nil, "phoneNumberVerified": nil, "username": nil, "displayUsername": nil} {
				v, ok := user[k]
				require.True(t, ok, "%s missing: %v", k, user)
				require.Equal(t, want, v, k)
			}

			// Step 3: without the plugins again: the columns stay (never dropped), goauth neither reads nor writes them
			s = server(t, openSameDB(t, db), cfg)
			require.Subset(t, columnsOf(t, db, prefix+"user"), pluginUserColumns)
			user = userJSON(t, s, "again@example.com")
			require.NotContains(t, user, "role")
			// a database default fills the ignored column of the new row
			banned := scalar(t, db, "SELECT "+q(db, "banned")+" FROM "+q(db, prefix+"user")+" WHERE "+q(db, "email")+" = ?", "again@example.com")
			require.Contains(t, []any{false, int64(0), "0", "false"}, banned)
		})
	}
}

// openSameDB returns a new connection to db's database: GORM caches parsed models per connection, and a new
// SetupGoAuth with other plugins needs a connection that hasn't parsed them yet.
func openSameDB(t *testing.T, db *gorm.DB) *gorm.DB {
	t.Helper()
	other, err := gorm.Open(db.Dialector, &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	if sqlDB, err := other.DB(); err == nil && db.Dialector.Name() == "sqlite" {
		sqlDB.SetMaxOpenConns(1)
	}
	return other
}

// setupWith runs SetupGoAuth on db with opts changes and returns its error.
func setupWith(db *gorm.DB, change func(*goauth.GoAuthOptions)) (*goauth.GoAuth, error) {
	o := goauth.GoAuthOptions{Conn: db, AuthConfig: config.AuthConfig{BaseURL: "http://127.0.0.1:8080", Secret: compattest.TestSecret}}
	change(&o)
	return goauth.SetupGoAuth(context.Background(), humago.New(http.NewServeMux(), huma.DefaultConfig("e2e", "1")), o)
}

// TestGORMRepositoriesRejectAdditionalFields: the hand-written GORM repositories can't store
// additionalFields, so SetupGoAuth refuses the combination instead of losing the values.
func TestGORMRepositoriesRejectAdditionalFields(t *testing.T) {
	db := openDB(t, helpers.DBTypeSQLite, "e2e_gormrepos")
	_, err := setupWith(db, func(o *goauth.GoAuthOptions) {
		o.GORMRepositories = true
		o.User.AdditionalFields = map[string]schema.Field{"plan": {Type: schema.String}}
	})
	require.ErrorContains(t, err, "GORMRepositories doesn't store additionalFields")
	// without additionalFields it starts, with every plugin column kept (the Go structs carry them)
	db = openDB(t, helpers.DBTypeSQLite, "e2e_gormrepos2")
	_, err = setupWith(db, func(o *goauth.GoAuthOptions) { o.GORMRepositories = true })
	require.NoError(t, err)
	require.Contains(t, columnsOf(t, db, "user"), "two_factor_enabled")
}
