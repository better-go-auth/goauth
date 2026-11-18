package adapterrepo_test

import (
	"context"
	"testing"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/adapter/gormadapter"
	"github.com/better-go-auth/goauth/src/adapter/gormadapter/gormtest"
	"github.com/better-go-auth/goauth/src/adapter/memory"
	"github.com/better-go-auth/goauth/src/app/repository/adapterrepo"
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/app/repository/repotest"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/models"
	coremigrator "github.com/better-go-auth/goauth/src/models/migration/core-migration"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/stretchr/testify/require"
)

// registry is the core schema plus repotest's extra fields.
func registry(prefix string) *schema.Registry {
	return schema.MustBuild(schema.Options{TablePrefix: prefix, Models: repotest.ExtraFields()})
}

func TestContract_Memory(t *testing.T) {
	newRepos := func(t *testing.T) repo_interfaces.IAuthRepos {
		reg := registry("")
		return adapterrepo.MustNew(memory.New(reg), reg)
	}
	repotest.Run(t, newRepos)
	repotest.RunExtraFields(t, newRepos)
}

// TestContract_GORM runs the repository contract through the GORM adapter on SQLite, Postgres and MySQL
// (the last two skip without Docker or TEST_POSTGRES_URL / TEST_MYSQL_URL). Tables come from the
// production core migrator (AutoMigrate of the Go models), extra columns are added on top.
func TestContract_GORM(t *testing.T) {
	for _, dialect := range gormtest.Dialects {
		t.Run(string(dialect), func(t *testing.T) {
			db := gormtest.OpenIsolated(t, dialect, "adapterrepo_contract")
			const prefix = "arp_"
			db.Config.NamingStrategy = gormutil.NewNamingStrategy(prefix, nil)
			reg := registry(prefix)
			newRepos := func(t *testing.T) repo_interfaces.IAuthRepos {
				// Step 1: production tables, then the additionalFields columns
				gormtest.Reset(t, db, reg)
				require.NoError(t, coremigrator.NewGORMAdminMigrator(db).Migrate(context.Background()))
				require.NoError(t, gormtest.Migrate(db, reg))
				return adapterrepo.MustNew(gormadapter.New(db, reg), reg)
			}
			repotest.Run(t, newRepos)
			repotest.RunExtraFields(t, newRepos)
		})
	}
}

// TestStaticAndExtraMapping checks a full user round trip through the memory adapter: every static field
// keeps its value and type, and extras land in Extra.
func TestStaticAndExtraMapping(t *testing.T) {
	ctx := context.Background()
	reg := registry("")
	a := memory.New(reg)
	r := adapterrepo.MustNew(a, reg)

	// Step 1: a user with most static fields set
	phone, username, bio := "+15550003333", "map_user", "hello"
	u := &models.User{UserDto: models.UserDto{
		Email: " Map@Example.com ", FirstName: "Ada", LastName: "Lovelace", Role: "admin",
		PhoneNumber: &phone, Username: &username, Bio: &bio, TwoFactorEnabled: true,
	}}
	schema.Set(u, "score", 3)
	created, err := r.CreateUser(ctx, u)
	require.NoError(t, err)
	require.Same(t, u, created, "the passed struct is filled in place, like GORM")
	require.Equal(t, "map@example.com", created.Email)
	require.Equal(t, "Ada Lovelace", created.Name, "PrepareSave derives the name")
	require.Equal(t, "en", created.Locale, "GORM tag default")

	// Step 2: the stored record uses registry names and canonical types
	rec, err := a.FindOne(ctx, schema.ModelUser, []adapter.Where{{Field: "id", Value: created.ID}})
	require.NoError(t, err)
	require.Equal(t, "admin", rec["role"])
	require.Equal(t, phone, rec["phoneNumber"])
	require.Equal(t, true, rec["twoFactorEnabled"])
	require.Equal(t, 3.0, rec["score"])
	require.Nil(t, rec["deletedAt"])

	// Step 3: reading back gives the same typed values
	got, err := r.FindUserByID(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "admin", string(got.Role))
	require.Equal(t, username, *got.Username)
	require.Equal(t, bio, *got.Bio)
	require.Nil(t, got.Image)
	require.True(t, got.TwoFactorEnabled)
	require.Equal(t, map[string]any{"score": 3.0, "loyaltyTier": "bronze"}, got.Extra)
	require.True(t, created.CreatedAt.Equal(got.CreatedAt))

	// Step 4: update keys may be Go names, registry names or GORM column names
	up, err := r.UpdateUser(ctx, created.ID, map[string]interface{}{"FirstName": "A", "lastName": "L", "display_name": "AL", "BanReason": nil})
	require.NoError(t, err)
	require.Equal(t, "A", up.FirstName)
	require.Equal(t, "L", up.LastName)
	require.Equal(t, "AL", *up.DisplayName)
	_, err = r.UpdateUser(ctx, created.ID, map[string]interface{}{"Sessions": nil})
	require.Error(t, err, "relations are not fields")

	// Step 5: not-found errors are autherr 404s, like the other repositories
	_, err = r.FindUserByID(ctx, "missing")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

// TestRegistryWithoutPluginColumns: when a plugin's columns are dropped from the registry, the repositories
// still work and lookups on those columns find nothing.
func TestRegistryWithoutPluginColumns(t *testing.T) {
	ctx := context.Background()
	reg := schema.MustBuild(schema.Options{InstalledPlugins: []string{}})
	r := adapterrepo.MustNew(memory.New(reg), reg)
	phone := "+15550004444"
	u := &models.User{UserDto: models.UserDto{Email: "np@example.com", PhoneNumber: &phone}}
	created, err := r.CreateUser(ctx, u)
	require.NoError(t, err)
	require.Nil(t, created.PhoneNumber, "the column doesn't exist, so the value isn't stored")
	_, err = r.FindUserByPhoneNumber(ctx, phone)
	require.Error(t, err)
	require.NoError(t, r.SoftDeleteUser(ctx, created.ID))
	_, err = r.FindUserByID(ctx, created.ID)
	require.Error(t, err)
}
