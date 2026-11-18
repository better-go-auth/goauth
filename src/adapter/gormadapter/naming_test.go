package gormadapter_test

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/better-go-auth/goauth/src/adapter/gormadapter"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/models"
	coremigrator "github.com/better-go-auth/goauth/src/models/migration/core-migration"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	gormschema "gorm.io/gorm/schema"
)

// TestSnakeRegistryMatchesAutoMigratedSchema is the compatibility guarantee of ColumnCase=snake: the
// registry's tables and columns are exactly what goauth's production migrator (GORM AutoMigrate through
// gormutil's naming strategy) creates, so existing databases keep working.
func TestSnakeRegistryMatchesAutoMigratedSchema(t *testing.T) {
	for _, prefix := range []string{"", "auth_"} {
		t.Run("prefix="+prefix, func(t *testing.T) {
			// Step 1: the production schema, built by the core migrator
			dsn := fmt.Sprintf("file:naming_%s?mode=memory&cache=shared", uuid.NewString())
			db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
				Logger:         logger.Discard,
				NamingStrategy: gormutil.NewNamingStrategy(prefix, map[string]string{"user": "users"}),
			})
			require.NoError(t, err)
			require.NoError(t, coremigrator.NewGORMAdminMigrator(db).Migrate(context.Background()))

			// Step 2: the registry with the same naming options
			reg := schema.MustBuild(schema.Options{TablePrefix: prefix, TableNames: map[string]string{"user": "users"}})
			snap, err := gormadapter.NewBackend(db).Inspect(context.Background())
			require.NoError(t, err)
			require.True(t, schema.Diff(reg, snap).Empty(), "%+v", schema.Diff(reg, snap).Changes)

			// Step 3: and nothing more: every column of the core tables is in the registry
			for _, m := range reg.Models() {
				table, ok := snap.Table(m.Table())
				require.True(t, ok, m.Table())
				var dbCols, regCols []string
				for _, c := range table.Columns {
					dbCols = append(dbCols, c.Name)
				}
				for _, f := range m.Fields() {
					regCols = append(regCols, f.Column)
				}
				sort.Strings(dbCols)
				sort.Strings(regCols)
				require.Equal(t, dbCols, regCols, m.Name())
			}
			require.Equal(t, prefix+"users", reg.Table("user"))
		})
	}
}

// TestSnakeCaseEqualsGORM checks schema.SnakeCase against GORM's own naming on the models' Go field names
// and on unusual names.
func TestSnakeCaseEqualsGORM(t *testing.T) {
	ns := gormschema.NamingStrategy{}
	names := []string{"HTTPSEnabled", "LoyaltyTierXYZ", "Field1Name", "Address2", "A", "LastLoginIP", "CallbackURL", "IDToken", "OAuthToken", "JSONData", "UserUUID"}
	for _, model := range []any{&models.User{}, &models.Session{}, &models.Account{}, &models.Verification{}} {
		s, err := gormschema.Parse(model, &sync.Map{}, ns)
		require.NoError(t, err)
		for _, f := range s.Fields {
			if f.DBName != "" {
				names = append(names, f.Name)
			}
		}
	}
	for _, n := range names {
		// the registry spells field names in lowerCamel; SnakeCase must not care about the first letter
		lower := strings.ToLower(n[:1]) + n[1:]
		require.Equal(t, ns.ColumnName("", n), schema.SnakeCase(lower), n)
		require.Equal(t, ns.ColumnName("", n), schema.SnakeCase(n), n)
	}
}
