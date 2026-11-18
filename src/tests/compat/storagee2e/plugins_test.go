package storagee2e

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"testing"

	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/adapter/gormadapter/gormtest"
	"github.com/better-go-auth/goauth/src/adapter/memory"
	"github.com/better-go-auth/goauth/src/app/repository/adapterrepo"
	"github.com/better-go-auth/goauth/src/config"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/admin"
	adminrepo "github.com/better-go-auth/goauth/src/plugins/admin/repository"
	jwtplugin "github.com/better-go-auth/goauth/src/plugins/jwt"
	jwtconfig "github.com/better-go-auth/goauth/src/plugins/jwt/config"
	"github.com/better-go-auth/goauth/src/plugins/org"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	"github.com/better-go-auth/goauth/src/plugins/passkey"
	pkconfig "github.com/better-go-auth/goauth/src/plugins/passkey/config"
	twofactor "github.com/better-go-auth/goauth/src/plugins/two-factor"
	tfconfig "github.com/better-go-auth/goauth/src/plugins/two-factor/config"
	"github.com/better-go-auth/goauth/src/schema"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
	"github.com/stretchr/testify/require"
)

// storagePlugins returns the plugins that store their own rows (organization with teams and dynamic access
// control, two-factor, passkey, jwt) plus admin, which reads and writes the core models.
func storagePlugins(t *testing.T) []plugin.Plugin {
	t.Helper()
	adminPlugin, err := admin.New(adminrepo.AdminRepositories{})
	require.NoError(t, err)
	orgPlugin, err := org.New(org.OrgOptions{Config: orgconfig.OrgConfig{
		Teams:                &orgconfig.TeamsConfig{Enabled: true},
		DynamicAccessControl: &orgconfig.DynamicAccessControlConfig{Enabled: true},
	}})
	require.NoError(t, err)
	return []plugin.Plugin{
		jwtplugin.New(jwtconfig.JWTConfig{}),
		adminPlugin,
		orgPlugin,
		twofactor.New(tfconfig.Config{Issuer: "e2e"}),
		passkey.New(pkconfig.PasskeyConfig{RPID: "127.0.0.1", RPName: "e2e", Origin: []string{"http://127.0.0.1:8080"}}),
	}
}

// switchUser gives s the cookie jar of another browser (nil: a new, empty one) and returns the previous one.
func switchUser(s *compattest.Server, jar *cookiejar.Jar) *cookiejar.Jar {
	prev := s.Jar
	if jar == nil {
		jar, _ = cookiejar.New(nil)
	}
	s.Jar = jar
	s.Client.Jar = jar
	return prev
}

// signUp creates a user through the API (the current jar holds its session) and returns its id.
func signUp(t *testing.T, s *compattest.Server, email string) string {
	t.Helper()
	res := s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": email, "password": password, "name": "Plugin User"})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	var body struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	res.JSON(t, &body)
	require.NotEmpty(t, body.User.ID)
	return body.User.ID
}

// ok asserts a 200 response and decodes it into v (when not nil).
func ok(t *testing.T, res *compattest.Response, v any) {
	t.Helper()
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	if v != nil {
		res.JSON(t, v)
	}
}

// pluginFlows drives every storage plugin through HTTP: organizations with invitations, members, teams and
// dynamic roles, two-factor setup, JWT keys, the passkey list and admin user management. checkID validates
// every id the server returns (e.g. integers with serial ids).
func pluginFlows(t *testing.T, s *compattest.Server, checkID func(t *testing.T, id string)) {
	t.Helper()
	ctx := context.Background()
	suffix := strconv.FormatInt(int64(len(t.Name())), 10)

	// Step 1: two users; the owner becomes an admin (role written through the adapter)
	ownerJar := switchUser(s, nil)
	memberID := signUp(t, s, "member"+suffix+"@example.com")
	memberJar := switchUser(s, ownerJar)
	ownerID := signUp(t, s, "owner"+suffix+"@example.com")
	checkID(t, ownerID)
	checkID(t, memberID)
	_, err := s.Auth.Adapter().Update(ctx, schema.ModelUser, []adapter.Where{{Field: "id", Value: ownerID}}, adapter.Record{"role": "admin"})
	require.NoError(t, err)
	// a new session carries the new role (sessions cache the user)
	ok(t, s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "owner" + suffix + "@example.com", "password": password}), nil)

	// Step 2: organization, invitation accepted by the member, members with their users
	var orgBody struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
	}
	ok(t, s.Post(t, "/api/auth/organization/create", map[string]any{"name": "Acme", "slug": "acme-" + suffix}), &orgBody)
	checkID(t, orgBody.ID)
	var inv struct {
		ID string `json:"id"`
	}
	ok(t, s.Post(t, "/api/auth/organization/invite-member", map[string]any{
		"email": "member" + suffix + "@example.com", "role": "member", "organizationId": orgBody.ID,
	}), &inv)
	checkID(t, inv.ID)
	ownerJar = switchUser(s, memberJar)
	ok(t, s.Post(t, "/api/auth/organization/accept-invitation", map[string]any{"invitationId": inv.ID}), nil)
	memberJar = switchUser(s, ownerJar)
	var members struct {
		Members []struct {
			ID     string `json:"id"`
			UserID string `json:"userId"`
			Role   string `json:"role"`
			User   struct {
				Email string `json:"email"`
			} `json:"user"`
		} `json:"members"`
		Total int `json:"total"`
	}
	ok(t, s.Get(t, "/api/auth/organization/list-members?organizationId="+orgBody.ID), &members)
	require.Len(t, members.Members, 2)
	emails, roles := map[string]string{}, map[string]string{}
	for _, m := range members.Members {
		checkID(t, m.ID)
		emails[m.UserID] = m.User.Email
		roles[m.UserID] = m.Role
	}
	require.Equal(t, "owner", roles[ownerID])
	require.Equal(t, "member", roles[memberID])
	require.Equal(t, "member"+suffix+"@example.com", emails[memberID])
	require.Equal(t, "owner"+suffix+"@example.com", emails[ownerID])

	// Step 3: a team with the member in it
	var team struct {
		ID string `json:"id"`
	}
	ok(t, s.Post(t, "/api/auth/organization/create-team", map[string]any{"name": "Core", "organizationId": orgBody.ID}), &team)
	checkID(t, team.ID)
	ok(t, s.Post(t, "/api/auth/organization/add-team-member", map[string]any{"teamId": team.ID, "userId": memberID}), nil)
	ownerJar = switchUser(s, memberJar)
	var teams []struct {
		ID string `json:"id"`
	}
	ok(t, s.Get(t, "/api/auth/organization/list-user-teams"), &teams)
	require.NotEmpty(t, teams)
	require.Equal(t, team.ID, teams[len(teams)-1].ID)
	memberJar = switchUser(s, ownerJar)

	// Step 4: a dynamic role (organizationRole row with a JSON permission document)
	ok(t, s.Post(t, "/api/auth/organization/create-role", map[string]any{
		"role": "auditor", "permission": map[string][]string{"member": {"update"}}, "organizationId": orgBody.ID,
	}), nil)
	var dynRoles []struct {
		Role       string              `json:"role"`
		Permission map[string][]string `json:"permission"`
	}
	ok(t, s.Get(t, "/api/auth/organization/list-roles?organizationId="+orgBody.ID), &dynRoles)
	require.Len(t, dynRoles, 1)
	require.Equal(t, "auditor", dynRoles[0].Role)
	require.Equal(t, []string{"update"}, dynRoles[0].Permission["member"])

	// Step 5: two-factor setup stores the twoFactor row
	var tf struct {
		TotpURI     string   `json:"totpURI"`
		BackupCodes []string `json:"backupCodes"`
	}
	ok(t, s.Post(t, "/api/auth/two-factor/enable", map[string]any{"password": password}), &tf)
	require.NotEmpty(t, tf.TotpURI)
	require.NotEmpty(t, tf.BackupCodes)
	var uri struct {
		TotpURI string `json:"totpURI"`
	}
	ok(t, s.Post(t, "/api/auth/two-factor/get-totp-uri", map[string]any{"password": password}), &uri)
	// the same stored secret (better-auth's get-totp-uri uses the app name as issuer)
	enabled, err := url.Parse(tf.TotpURI)
	require.NoError(t, err)
	read, err := url.Parse(uri.TotpURI)
	require.NoError(t, err)
	require.Equal(t, enabled.Query().Get("secret"), read.Query().Get("secret"))

	// Step 6: JWT signed with a key stored in jwks, published at /jwks
	var tok struct {
		Token string `json:"token"`
	}
	ok(t, s.Get(t, "/api/auth/token"), &tok)
	require.NotEmpty(t, tok.Token)
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	ok(t, s.Get(t, "/api/auth/jwks"), &jwks)
	require.Len(t, jwks.Keys, 1)
	checkID(t, jwks.Keys[0].Kid)

	// Step 7: passkeys (none registered)
	var pks []any
	ok(t, s.Get(t, "/api/auth/passkey/list-user-passkeys"), &pks)
	require.Empty(t, pks)

	// Step 8: admin: list, ban and unban users
	var list struct {
		Users []struct {
			ID string `json:"id"`
		} `json:"users"`
		Total int `json:"total"`
	}
	ok(t, s.Get(t, "/api/auth/admin/list-users?searchValue=example.com&searchField=email&sortBy=createdAt&sortDirection=asc"), &list)
	require.Equal(t, 2, list.Total)
	require.Equal(t, memberID, list.Users[0].ID)
	var banned struct {
		User struct {
			Banned bool `json:"banned"`
		} `json:"user"`
	}
	ok(t, s.Post(t, "/api/auth/admin/ban-user", map[string]any{"userId": memberID, "banReason": "spam"}), &banned)
	require.True(t, banned.User.Banned)
	ok(t, s.Post(t, "/api/auth/admin/unban-user", map[string]any{"userId": memberID}), &banned)
	require.False(t, banned.User.Banned)

	// Step 9: deleting the organization removes its members, invitations, teams and roles
	ok(t, s.Post(t, "/api/auth/organization/delete", map[string]any{"organizationId": orgBody.ID}), nil)
	for _, model := range []string{"member", "invitation", "team", "teamMember", "organizationRole", "organization"} {
		n, err := s.Auth.Adapter().Count(ctx, model, nil)
		require.NoError(t, err)
		require.Zero(t, n, model)
	}
}

// anyID accepts every non-empty id.
func anyID(t *testing.T, id string) {
	t.Helper()
	require.NotEmpty(t, id)
}

// serialID requires an integer id (IDFormat serial).
func serialID(t *testing.T, id string) {
	t.Helper()
	_, err := strconv.ParseInt(id, 10, 64)
	require.NoError(t, err, "id %q", id)
}

// TestPluginsWithSerialIDs: the storage plugins work with database-generated serial ids and camelCase
// columns on every dialect (their tables come from the schema registry; references are integers).
func TestPluginsWithSerialIDs(t *testing.T) {
	for _, dialect := range gormtest.Dialects {
		t.Run(string(dialect), func(t *testing.T) {
			db := openDB(t, dialect, "e2e_plugins_serial")
			prefix := prefixFor(dialect, "e2e_plugins_serial")
			s := server(t, db, func(c *config.AuthConfig) {
				c.GoAuth.TablePrefix = prefix
				c.GoAuth.ColumnCase = schema.Camel
				c.Advanced.Database.IDFormat = config.IDFormatSerial
			}, storagePlugins(t)...)
			pluginFlows(t, s, serialID)
		})
	}
}

// TestPluginsWithDatabaseIDs: the storage plugins work when the database generates (uuid / random) ids.
func TestPluginsWithDatabaseIDs(t *testing.T) {
	for _, dialect := range gormtest.Dialects {
		t.Run(string(dialect), func(t *testing.T) {
			db := openDB(t, dialect, "e2e_plugins_dbids")
			prefix := prefixFor(dialect, "e2e_plugins_dbids")
			s := server(t, db, func(c *config.AuthConfig) {
				c.GoAuth.TablePrefix = prefix
				c.Advanced.Database.IDFormat = config.IDFormatDatabase
			}, storagePlugins(t)...)
			pluginFlows(t, s, anyID)
		})
	}
}

// TestPluginsOnMemoryAdapter: the storage plugins work without a SQL database: goauth runs on the memory
// adapter (adapter-based Repositories, no Conn, no TxManager).
func TestPluginsOnMemoryAdapter(t *testing.T) {
	s := compattest.NewServer(t, func(o *goauth.GoAuthOptions) {
		o.Plugins = append(o.Plugins, storagePlugins(t)...)
		o.GoAuth.ColumnCase = schema.Snake
	}, func(o *goauth.GoAuthOptions) {
		// the memory adapter needs the registry of exactly these options (plugin tables included)
		reg, err := goauth.Schema(*o)
		require.NoError(t, err)
		o.Conn = nil
		o.Repositories = adapterrepo.MustNew(memory.New(reg), reg)
	})
	require.NotNil(t, s.Auth.Adapter())
	require.Equal(t, "memory", s.Auth.Adapter().ID())
	pluginFlows(t, s, anyID)
}
