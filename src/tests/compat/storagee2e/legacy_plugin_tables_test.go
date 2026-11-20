package storagee2e

import (
	"context"
	"net/http"
	"sort"
	"testing"

	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/adapter/gormadapter"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/config"
	coremodels "github.com/better-go-auth/goauth/src/models"
	core_migration "github.com/better-go-auth/goauth/src/models/migration/core-migration"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	jwtplugin "github.com/better-go-auth/goauth/src/plugins/jwt"
	jwtmodels "github.com/better-go-auth/goauth/src/plugins/jwt/models"
	"github.com/better-go-auth/goauth/src/plugins/org"
	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
	"github.com/better-go-auth/goauth/src/plugins/passkey"
	pkmodels "github.com/better-go-auth/goauth/src/plugins/passkey/models"
	twofactor "github.com/better-go-auth/goauth/src/plugins/two-factor"
	tfmodels "github.com/better-go-auth/goauth/src/plugins/two-factor/models"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// legacyStructs are the GORM structs older goauth versions AutoMigrated for the plugin tables (the plugin
// migrators before missing-tasks 2.9), keyed by logical model name.
func legacyStructs(dialect helpers.DatabaseType) map[string]any {
	out := map[string]any{
		orgmodels.ModelOrganization: &orgmodels.Organization{}, orgmodels.ModelMember: &orgmodels.Member{},
		orgmodels.ModelInvitation: &orgmodels.Invitation{}, orgmodels.ModelTeam: &orgmodels.Team{},
		orgmodels.ModelTeamMember: &orgmodels.TeamMember{}, orgmodels.ModelOrganizationRole: &orgmodels.OrganizationRole{},
		tfmodels.ModelTwoFactor: &tfmodels.TwoFactor{}, jwtmodels.ModelJWKS: &jwtmodels.JWK{},
	}
	// the old passkey struct indexes a varchar(1024) credential id, which MySQL can't index (the GORM
	// migrator never worked there), so there are no MySQL passkey tables to upgrade
	if dialect != helpers.DBTypeMySQL {
		out[pkmodels.ModelPasskey] = &pkmodels.Passkey{}
	}
	return out
}

// legacyPlugins returns the plugins whose tables used to be GORM structs, with every optional table on.
func legacyPlugins(t *testing.T) []plugin.Plugin {
	t.Helper()
	all := storagePlugins(t)
	out := make([]plugin.Plugin, 0, len(all))
	for _, p := range all {
		switch p.(type) {
		case *org.OrgPlugin, *twofactor.Plugin, *passkey.Plugin, *jwtplugin.Plugin:
			out = append(out, p)
		}
	}
	return out
}

// createLegacyTables builds the database an older goauth created: the core GORM bootstrap and GORM
// AutoMigrate of the plugin structs (with the organization's session foreign key), named by the naming
// strategy of that version (registry columns for the core tables only).
func createLegacyTables(t *testing.T, db *gorm.DB, dialect helpers.DatabaseType, cc schema.ColumnCase, prefix string) {
	t.Helper()
	// Step 1: the old naming strategy: the registry had only the core models
	core, err := goauth.Schema(goauth.GoAuthOptions{AuthConfig: config.AuthConfig{GoAuth: config.GoAuthConfig{ColumnCase: cc, TablePrefix: prefix}}})
	require.NoError(t, err)
	db.Config.NamingStrategy = gormutil.NewNamingStrategy(prefix, nil, gormutil.WithRegistry(core))
	// Step 2: core tables, then the plugin structs (what the plugin migrators ran)
	require.NoError(t, core_migration.NewGORMAdminMigrator(db).Migrate(context.Background()))
	for _, model := range sortedKeys(legacyStructs(dialect)) {
		require.NoError(t, db.AutoMigrate(legacyStructs(dialect)[model]), model)
	}
	if !db.Migrator().HasConstraint(&orgmodels.Organization{}, "Sessions") {
		require.NoError(t, db.Migrator().CreateConstraint(&orgmodels.Organization{}, "Sessions"))
	}
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestLegacyPluginTablesMatchRegistry: the plugin tables an older goauth created with GORM AutoMigrate have
// exactly the columns of the plugins' registry schema (snake_case on every dialect, camelCase on SQLite),
// so goauth's migrator adds no table or column to them, and goauth starts on such a database in auto and
// verify mode and reads and writes the old rows.
func TestLegacyPluginTablesMatchRegistry(t *testing.T) {
	cases := []struct {
		dialect helpers.DatabaseType
		cc      schema.ColumnCase
	}{
		{helpers.DBTypeSQLite, schema.Snake}, {helpers.DBTypeSQLite, schema.Camel},
		{helpers.DBTypePostgres, schema.Snake}, {helpers.DBTypeMySQL, schema.Snake},
	}
	for _, tc := range cases {
		t.Run(string(tc.dialect)+"_"+string(tc.cc), func(t *testing.T) {
			ctx := context.Background()
			name := "e2e_legacy_" + string(tc.cc)
			db := openDB(t, tc.dialect, name)
			prefix := prefixFor(tc.dialect, name)
			createLegacyTables(t, db, tc.dialect, tc.cc, prefix)
			cfg := func(c *config.AuthConfig) {
				c.GoAuth.TablePrefix = prefix
				c.GoAuth.ColumnCase = tc.cc
			}

			// Step 1: the registry's columns are the old GORM columns, table by table
			opts := goauth.GoAuthOptions{Plugins: legacyPlugins(t), AuthConfig: config.AuthConfig{GoAuth: config.GoAuthConfig{ColumnCase: tc.cc, TablePrefix: prefix}}}
			reg, err := goauth.Schema(opts)
			require.NoError(t, err)
			for _, model := range sortedKeys(legacyStructs(tc.dialect)) {
				m, ok := reg.Model(model)
				require.True(t, ok, model)
				var want []string
				for _, f := range m.Fields() {
					want = append(want, f.Column)
				}
				sort.Strings(want)
				got := columnsOf(t, db, m.Table())
				sort.Strings(got)
				require.Equal(t, want, got, "columns of %s", m.Table())
			}

			// Step 2: goauth's migrator adds no table or column to them (only indexes better-auth declares)
			plan, err := gormadapter.NewBackend(db).Plan(ctx, reg)
			require.NoError(t, err)
			for _, c := range plan.Changes {
				if _, legacy := legacyStructs(tc.dialect)[c.Model]; legacy {
					require.Equal(t, schema.AddIndex, c.Kind, "%s %s", c.Kind, c.Table)
				}
			}

			// Step 3: rows written by the old version
			now := coremodels.TimeNow()
			user := &coremodels.User{Base: coremodels.Base{ID: "legacy-user", CreatedAt: now, UpdatedAt: now}}
			user.Name, user.Email = "Legacy", "legacy@example.com"
			require.NoError(t, db.Create(user).Error)
			legacyOrg := &orgmodels.Organization{Base: coremodels.Base{ID: "legacy-org", CreatedAt: now, UpdatedAt: now}, Name: "Legacy", Slug: "legacy", CreatedBy: user.ID, Status: orgmodels.OrgStatusActive}
			require.NoError(t, db.Create(legacyOrg).Error)
			require.NoError(t, db.Create(&orgmodels.Member{Base: coremodels.Base{ID: "legacy-member", CreatedAt: now, UpdatedAt: now}, OrganizationID: legacyOrg.ID, UserID: user.ID, Role: orgmodels.OrgRoleOwner}).Error)
			require.NoError(t, db.Create(&orgmodels.OrganizationRole{Base: coremodels.Base{ID: "legacy-role", CreatedAt: now, UpdatedAt: now}, OrganizationID: legacyOrg.ID, Role: "auditor", Permission: orgmodels.Permission{"member": {"update"}}}).Error)
			require.NoError(t, db.Select("*").Create(&tfmodels.TwoFactor{ID: "legacy-2fa", Secret: "s", BackupCodes: "b", UserID: user.ID}).Error)
			if _, ok := legacyStructs(tc.dialect)[pkmodels.ModelPasskey]; ok {
				require.NoError(t, db.Create(&pkmodels.Passkey{ID: "legacy-pk", PublicKey: "pk", UserID: user.ID, CredentialID: "cred", Counter: 7, DeviceType: "singleDevice", BackedUp: true, CreatedAt: &now}).Error)
			}

			// Step 4: goauth starts on the old tables (auto mode, then verify mode: nothing is missing)
			plugins := legacyPlugins(t)
			s := server(t, db, cfg, plugins...)
			_, err = setup(db, func(c *config.AuthConfig) {
				cfg(c)
				c.GoAuth.Migrations.Mode = config.MigrationsVerify
			}, legacyPlugins(t)...)
			require.NoError(t, err)

			// Step 5: the plugins read the old rows through the adapter
			orgPlugin, isOrg := s.Auth.Plugin(org.PluginID).(*org.OrgPlugin)
			require.True(t, isOrg)
			repos := orgPlugin.Repositories()
			got, err := repos.IOrgRepo.GetOrgBySlug(ctx, "legacy")
			require.NoError(t, err)
			require.Equal(t, legacyOrg.ID, got.ID)
			require.Equal(t, user.ID, got.CreatedBy)
			m, err := repos.IMemberRepo.GetMemberByOrgAndUser(ctx, legacyOrg.ID, user.ID)
			require.NoError(t, err)
			require.Equal(t, orgmodels.OrgRoleOwner, m.Role)
			require.NotNil(t, m.User)
			require.Equal(t, "legacy@example.com", m.User.Email)
			role, err := repos.IOrganizationRoleRepo.GetRole(ctx, legacyOrg.ID, "auditor")
			require.NoError(t, err)
			require.Equal(t, []string{"update"}, role.Permission["member"])
			tf, err := s.Auth.Adapter().FindOne(ctx, tfmodels.ModelTwoFactor, []adapter.Where{{Field: "userId", Value: user.ID}})
			require.NoError(t, err)
			require.Equal(t, "s", tf["secret"])
			require.Equal(t, false, tf["verified"])
			if _, ok := legacyStructs(tc.dialect)[pkmodels.ModelPasskey]; ok {
				pk, err := s.Auth.Adapter().FindOne(ctx, pkmodels.ModelPasskey, []adapter.Where{{Field: "credentialID", Value: "cred"}})
				require.NoError(t, err)
				require.EqualValues(t, 7, pk["counter"])
				require.Equal(t, true, pk["backedUp"])
			}

			// Step 6: new rows go into the old tables through HTTP (the old NOT NULL columns are filled)
			signUp(t, s, "new@example.com")
			var created struct {
				ID string `json:"id"`
			}
			ok(t, s.Post(t, "/api/auth/organization/create", map[string]any{"name": "New", "slug": "new-org"}), &created)
			ok(t, s.Post(t, "/api/auth/organization/invite-member", map[string]any{"email": "legacy@example.com", "role": "member", "organizationId": created.ID}), nil)
			ok(t, s.Post(t, "/api/auth/organization/create-team", map[string]any{"name": "Team", "organizationId": created.ID}), nil)
			ok(t, s.Post(t, "/api/auth/two-factor/enable", map[string]any{"password": password}), nil)
			ok(t, s.Get(t, "/api/auth/token"), nil)
			var jwks struct {
				Keys []struct {
					Kid string `json:"kid"`
				} `json:"keys"`
			}
			ok(t, s.Get(t, "/api/auth/jwks"), &jwks)
			require.Len(t, jwks.Keys, 1)
			key, err := s.Auth.Adapter().FindOne(ctx, jwtmodels.ModelJWKS, []adapter.Where{{Field: "id", Value: jwks.Keys[0].Kid}})
			require.NoError(t, err)
			require.NotEmpty(t, key["alg"])
			res := s.Get(t, "/api/auth/organization/list")
			require.Equal(t, http.StatusOK, res.Status, string(res.Body))
		})
	}
}
