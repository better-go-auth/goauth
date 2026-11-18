package schema_test

import (
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/schema"
	"github.com/stretchr/testify/require"
)

// columns returns field → column of one model.
func columns(t *testing.T, reg *schema.Registry, model string) map[string]string {
	t.Helper()
	m, ok := reg.Model(model)
	require.True(t, ok, model)
	out := map[string]string{}
	for _, f := range m.Fields() {
		out[f.Name] = f.Column
	}
	return out
}

func TestCoreModels_SnakeAndCamel(t *testing.T) {
	snake := schema.MustBuild(schema.Options{})
	camel := schema.MustBuild(schema.Options{ColumnCase: schema.Camel})

	// Step 1: tables are better-auth's model names in both layouts
	for _, reg := range []*schema.Registry{snake, camel} {
		require.Equal(t, "user", reg.Table("user"))
		require.Equal(t, "session", reg.Table("session"))
		require.Equal(t, "account", reg.Table("account"))
		require.Equal(t, "verification", reg.Table("verification"))
	}
	require.Equal(t, schema.Snake, snake.ColumnCase())

	// Step 2: snake columns are GORM's names, camel columns are the field names
	cases := map[string][3]string{ // model.field → {model, snake, camel}
		"user.emailVerified":             {"user", "email_verified", "emailVerified"},
		"user.lastLoginIP":               {"user", "last_login_ip", "lastLoginIP"},
		"user.phoneNumberVerified":       {"user", "phone_number_verified", "phoneNumberVerified"},
		"user.dateOfBirth":               {"user", "date_of_birth", "dateOfBirth"},
		"session.userId":                 {"session", "user_id", "userId"},
		"session.ipAddress":              {"session", "ip_address", "ipAddress"},
		"session.activeOrganizationId":   {"session", "active_organization_id", "activeOrganizationId"},
		"session.deviceId":               {"session", "device_id", "deviceId"},
		"account.idToken":                {"account", "id_token", "idToken"},
		"account.refreshTokenExpiresAt":  {"account", "refresh_token_expires_at", "refreshTokenExpiresAt"},
		"verification.callbackUrl":       {"verification", "callback_url", "callbackUrl"},
		"verification.expiresAt":         {"verification", "expires_at", "expiresAt"},
		"user.id":                        {"user", "id", "id"},
		"account.accessTokenExpiresAt":   {"account", "access_token_expires_at", "accessTokenExpiresAt"},
		"session.activeOrganizationRole": {"session", "active_organization_role", "activeOrganizationRole"},
		"user.twoFactorEnabled":          {"user", "two_factor_enabled", "twoFactorEnabled"},
		"user.displayUsername":           {"user", "display_username", "displayUsername"},
		"user.isAnonymous":               {"user", "is_anonymous", "isAnonymous"},
		"user.banExpires":                {"user", "ban_expires", "banExpires"},
		"session.impersonatedBy":         {"session", "impersonated_by", "impersonatedBy"},
		"session.lastUsedAt":             {"session", "last_used_at", "lastUsedAt"},
		"verification.userId":            {"verification", "user_id", "userId"},
		"account.providerId":             {"account", "provider_id", "providerId"},
		"user.createdAt":                 {"user", "created_at", "createdAt"},
		"session.activeOrganizationType": {"session", "active_organization_type", "activeOrganizationType"},
		"account.accountId":              {"account", "account_id", "accountId"},
		"user.lastSeen":                  {"user", "last_seen", "lastSeen"},
		"user.deletedAt":                 {"user", "deleted_at", "deletedAt"},
		"session.activeTeamId":           {"session", "active_team_id", "activeTeamId"},
		"session.deviceToken":            {"session", "device_token", "deviceToken"},
		"verification.identifier":        {"verification", "identifier", "identifier"},
		"session.expiresAt":              {"session", "expires_at", "expiresAt"},
		"user.banReason":                 {"user", "ban_reason", "banReason"},
		"session.userAgent":              {"session", "user_agent", "userAgent"},
		"account.refreshToken":           {"account", "refresh_token", "refreshToken"},
		"user.updatedAt":                 {"user", "updated_at", "updatedAt"},
		"account.userId":                 {"account", "user_id", "userId"},
		"user.firstName":                 {"user", "first_name", "firstName"},
		"session.deviceType":             {"session", "device_type", "deviceType"},
		"session.deviceName":             {"session", "device_name", "deviceName"},
		"verification.value":             {"verification", "value", "value"},
		"user.phoneNumber":               {"user", "phone_number", "phoneNumber"},
		"account.scope":                  {"account", "scope", "scope"},
		"user.lastLoginAt":               {"user", "last_login_at", "lastLoginAt"},
		"account.password":               {"account", "password", "password"},
		"account.accessToken":            {"account", "access_token", "accessToken"},
		"user.lastName":                  {"user", "last_name", "lastName"},
		"user.displayName":               {"user", "display_name", "displayName"},
		"verification.updatedAt":         {"verification", "updated_at", "updatedAt"},
		"session.token":                  {"session", "token", "token"},
		"session.createdAt":              {"session", "created_at", "createdAt"},
		"verification.createdAt":         {"verification", "created_at", "createdAt"},
		"account.createdAt":              {"account", "created_at", "createdAt"},
		"account.updatedAt":              {"account", "updated_at", "updatedAt"},
		"session.updatedAt":              {"session", "updated_at", "updatedAt"},
		"user.email":                     {"user", "email", "email"},
		"user.name":                      {"user", "name", "name"},
		"user.image":                     {"user", "image", "image"},
		"user.role":                      {"user", "role", "role"},
		"user.banned":                    {"user", "banned", "banned"},
		"user.username":                  {"user", "username", "username"},
		"user.bio":                       {"user", "bio", "bio"},
		"user.gender":                    {"user", "gender", "gender"},
		"user.locale":                    {"user", "locale", "locale"},
		"user.timezone":                  {"user", "timezone", "timezone"},
		"session.id":                     {"session", "id", "id"},
		"account.id":                     {"account", "id", "id"},
		"verification.id":                {"verification", "id", "id"},
	}
	for key, c := range cases {
		field := key[strings.Index(key, ".")+1:]
		require.Equal(t, c[1], snake.Column(c[0], field), "snake %s", key)
		require.Equal(t, c[2], camel.Column(c[0], field), "camel %s", key)
	}
	// Step 3: every core field is covered above (keeps the table in sync with core.go)
	total := 0
	for _, m := range snake.Models() {
		total += len(m.Fields())
	}
	require.Equal(t, total, len(cases))
}

func TestCoreModels_BetterAuthAttributes(t *testing.T) {
	reg := schema.MustBuild(schema.Options{})
	user, _ := reg.Model("user")

	// Step 1: core fields match better-auth's getAuthTables
	email, _ := user.Field("email")
	require.True(t, email.Unique && email.Required && email.Sortable)
	require.Equal(t, schema.OwnerCore, email.Owner)
	ev, _ := user.Field("emailVerified")
	require.False(t, ev.IsInput())
	require.Equal(t, false, ev.DefaultValue())
	updatedAt, _ := user.Field("updatedAt")
	require.NotNil(t, updatedAt.OnUpdate)

	// Step 2: plugin-owned fields carry their plugin ID; goauth fields are marked goauth
	role, _ := user.Field("role")
	require.Equal(t, schema.PluginAdmin, role.Owner)
	phone, _ := user.Field("phoneNumber")
	require.Equal(t, schema.PluginPhoneNumber, phone.Owner)
	require.True(t, phone.IsNullableUnique())
	first, _ := user.Field("firstName")
	require.Equal(t, schema.OwnerGoAuth, first.Owner)

	// Step 3: account token columns are never returned; references point at user.id
	account, _ := reg.Model("account")
	pw, _ := account.Field("password")
	require.False(t, pw.IsReturned())
	uid, _ := account.Field("userId")
	require.Equal(t, &schema.Reference{Model: "user", Field: "id", OnDelete: schema.Cascade}, uid.References)
	require.Len(t, account.Indexes(), 1)
	require.Equal(t, []string{"providerId", "accountId"}, account.Indexes()[0].Fields)

	// Step 4: field order starts with better-auth's core order
	names := []string{}
	for _, f := range user.Fields()[:7] {
		names = append(names, f.Name)
	}
	require.Equal(t, []string{"id", "name", "email", "emailVerified", "image", "createdAt", "updatedAt"}, names)

	// Step 5: input fields exclude better-auth core fields; output fields exclude returned:false
	for _, f := range user.InputFields() {
		require.NotEqual(t, schema.OwnerCore, f.Owner, f.Name)
	}
	for _, f := range account.OutputFields() {
		require.NotContains(t, []string{"password", "accessToken", "refreshToken", "idToken"}, f.Name)
	}
}

func TestBuild_NameResolution(t *testing.T) {
	reg, err := schema.Build(schema.Options{
		TablePrefix: "auth_",
		TableNames:  map[string]string{"user": "members", "session": "sessions"},
		Models: map[string]schema.ModelOptions{
			"user":    {ModelName: "users", Fields: map[string]string{"emailVerified": "is_verified"}},
			"account": {Fields: map[string]string{"userId": "owner"}},
		},
	})
	require.NoError(t, err)
	// Step 1: ModelName wins over TableNames, the prefix applies to both
	require.Equal(t, "auth_users", reg.Table("user"))
	require.Equal(t, "auth_sessions", reg.Table("session"))
	require.Equal(t, "auth_account", reg.Table("account"))
	// Step 2: Fields renames are used as is
	require.Equal(t, "is_verified", reg.Column("user", "emailVerified"))
	require.Equal(t, "owner", reg.Column("account", "userId"))
	user, _ := reg.Model("user")
	f, ok := user.FieldByColumn("is_verified")
	require.True(t, ok)
	require.Equal(t, "emailVerified", f.Name)
	// Step 3: unknown names give "" instead of panicking
	require.Equal(t, "", reg.Table("nope"))
	require.Equal(t, "", reg.Column("user", "nope"))
}

func TestBuild_MergeOrder(t *testing.T) {
	reg, err := schema.Build(schema.Options{
		Models: map[string]schema.ModelOptions{
			"user": {AdditionalFields: map[string]schema.Field{
				"loyaltyTier": {Type: schema.String, Default: "bronze"},
				"nickname":    {Type: schema.String, FieldName: "nick"},
			}},
			"session": {AdditionalFields: map[string]schema.Field{"region": {Type: schema.String}}},
		},
		Plugins: []schema.Plugin{
			{ID: "loyalty", Schema: schema.PluginSchema{
				"user": {Fields: map[string]schema.Field{"loyaltyTier": {Type: schema.Integer}}},
				"reward": {ModelName: "rewards", Fields: map[string]schema.Field{
					"userId": {Type: schema.String, Required: true, References: &schema.Reference{Model: "user", Field: "id"}},
					"points": {Type: schema.Integer, Required: true},
				}},
			}},
		},
	})
	require.NoError(t, err)

	// Step 1: the plugin wins over the configuration (better-auth's getFields order)
	user, _ := reg.Model("user")
	tier, ok := user.Field("loyaltyTier")
	require.True(t, ok)
	require.Equal(t, schema.Integer, tier.Type)
	require.Equal(t, "loyalty", tier.Owner)
	nick, _ := user.Field("nickname")
	require.Equal(t, "nick", nick.Column)
	require.Equal(t, schema.OwnerConfig, nick.Owner)
	region, _ := reg.Model("session")
	require.True(t, region.Has("region"))

	// Step 2: a plugin model becomes a table with an implicit id, after the core models
	reward, ok := reg.Model("reward")
	require.True(t, ok)
	require.Equal(t, "rewards", reward.Table())
	require.True(t, reward.Has("id"))
	require.Equal(t, "user_id", reward.Column("userId"))
	models := reg.Models()
	require.Equal(t, "reward", models[len(models)-1].Name())
}

func TestBuild_InstalledPlugins(t *testing.T) {
	// Step 1: nil keeps every plugin column (the Go models still carry them)
	all := schema.MustBuild(schema.Options{})
	user, _ := all.Model("user")
	require.True(t, user.Has("role") && user.Has("phoneNumber") && user.Has("username"))

	// Step 2: a list drops the columns of the plugins that are missing
	reg := schema.MustBuild(schema.Options{InstalledPlugins: []string{schema.PluginAdmin}})
	user, _ = reg.Model("user")
	require.True(t, user.Has("role"))
	require.False(t, user.Has("phoneNumber"))
	require.False(t, user.Has("twoFactorEnabled"))
	require.True(t, user.Has("firstName"), "goauth columns stay")
	session, _ := reg.Model("session")
	require.True(t, session.Has("impersonatedBy"))
	require.False(t, session.Has("activeOrganizationId"))
}

func TestBuild_ValidationErrors(t *testing.T) {
	cases := map[string]schema.Options{
		"duplicate column": {Models: map[string]schema.ModelOptions{"user": {AdditionalFields: map[string]schema.Field{
			"x": {Type: schema.String, FieldName: "email"},
		}}}},
		"duplicate column case-insensitive": {ColumnCase: schema.Camel, Models: map[string]schema.ModelOptions{"user": {AdditionalFields: map[string]schema.Field{
			"EMAIL": {Type: schema.String},
		}}}},
		"invalid type": {Models: map[string]schema.ModelOptions{"user": {AdditionalFields: map[string]schema.Field{
			"x": {Type: "text"},
		}}}},
		"missing type": {Models: map[string]schema.ModelOptions{"user": {AdditionalFields: map[string]schema.Field{
			"x": {},
		}}}},
		"enum on number": {Models: map[string]schema.ModelOptions{"user": {AdditionalFields: map[string]schema.Field{
			"x": {Type: schema.Number, Enum: []string{"a"}},
		}}}},
		"id type elsewhere": {Models: map[string]schema.ModelOptions{"user": {AdditionalFields: map[string]schema.Field{
			"x": {Type: schema.ID},
		}}}},
		"unknown reference model": {Models: map[string]schema.ModelOptions{"user": {AdditionalFields: map[string]schema.Field{
			"x": {Type: schema.String, References: &schema.Reference{Model: "team", Field: "id"}},
		}}}},
		"unknown reference field": {Models: map[string]schema.ModelOptions{"user": {AdditionalFields: map[string]schema.Field{
			"x": {Type: schema.String, References: &schema.Reference{Model: "session", Field: "nope"}},
		}}}},
		"options for unknown model":   {Models: map[string]schema.ModelOptions{"team": {ModelName: "teams"}}},
		"fields for unknown model":    {Models: map[string]schema.ModelOptions{"team": {AdditionalFields: map[string]schema.Field{"x": {Type: schema.String}}}}},
		"rename unknown field":        {Models: map[string]schema.ModelOptions{"user": {Fields: map[string]string{"nope": "x"}}}},
		"duplicate table":             {TableNames: map[string]string{"user": "session"}},
		"unknown column case":         {ColumnCase: "kebab"},
		"plugin without id":           {Plugins: []schema.Plugin{{Schema: schema.PluginSchema{"user": {}}}}},
		"index over unknown field":    {Plugins: []schema.Plugin{{ID: "p", Schema: schema.PluginSchema{"user": {Indexes: []schema.Index{{Fields: []string{"nope"}}}}}}}},
		"rename collides with column": {Models: map[string]schema.ModelOptions{"user": {Fields: map[string]string{"image": "email"}}}},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := schema.Build(opts)
			require.Error(t, err)
			require.True(t, strings.HasPrefix(err.Error(), "schema: "), err.Error())
		})
	}
}

func TestSnakeCase_MatchesGORMRules(t *testing.T) {
	for in, want := range map[string]string{
		"emailVerified":  "email_verified",
		"userId":         "user_id",
		"ID":             "id",
		"lastLoginIP":    "last_login_ip",
		"callbackUrl":    "callback_url",
		"CallbackURL":    "callback_url",
		"IPAddress":      "ip_address",
		"HTTPSEnabled":   "http_s_enabled", // GORM quirk: the HTTP initialism matches first
		"address2":       "address2",
		"Field1Name":     "field1_name",
		"already_snake":  "already_snake",
		"a":              "a",
		"A":              "a",
		"loyaltyTierXYZ": "loyalty_tier_xyz",
	} {
		require.Equal(t, want, schema.SnakeCase(in), in)
	}
}

func TestDiff(t *testing.T) {
	reg := schema.MustBuild(schema.Options{Models: map[string]schema.ModelOptions{
		"user": {AdditionalFields: map[string]schema.Field{"loyaltyTier": {Type: schema.String}}},
	}})
	user, _ := reg.Model("user")
	// Step 1: a snapshot with the user table missing loyalty_tier, and no other tables; the user indexes
	// exist under other names (indexes match by columns)
	snap := &schema.Snapshot{Tables: []schema.TableSnapshot{{Name: "USER"}}}
	for _, f := range user.Fields() {
		if f.Name != "loyaltyTier" {
			snap.Tables[0].Columns = append(snap.Tables[0].Columns, schema.ColumnSnapshot{Name: f.Column})
		}
	}
	for _, idx := range user.IndexSpecs() {
		snap.Tables[0].Indexes = append(snap.Tables[0].Indexes, schema.IndexSnapshot{Name: "x_" + idx.Name, Columns: idx.Columns, Unique: idx.Unique})
	}
	// Step 2: the plan adds the three other tables first, then the column, then the new tables' indexes
	plan := schema.Diff(reg, snap)
	require.False(t, plan.Empty())
	require.Same(t, reg, plan.Registry)
	var kinds []schema.ChangeKind
	for _, c := range plan.Changes {
		kinds = append(kinds, c.Kind)
	}
	require.Equal(t, []schema.ChangeKind{schema.AddTable, schema.AddTable, schema.AddTable, schema.AddColumn}, kinds[:4])
	require.Equal(t, "loyalty_tier", plan.Changes[3].Field.Column)
	for _, c := range plan.Changes[4:] {
		require.Equal(t, schema.AddIndex, c.Kind)
		require.NotEqual(t, "user", c.Model)
	}
	require.Contains(t, plan.Summary(), "add unique index idx_provider_account on account (provider_id, account_id)")
	require.True(t, (&schema.Plan{}).Empty())

	// Step 3: a non-unique index doesn't satisfy a unique need; a unique one satisfies an index need
	tbl := &schema.TableSnapshot{Indexes: []schema.IndexSnapshot{{Columns: []string{"email"}}, {Columns: []string{"user_id"}, Unique: true}}}
	require.False(t, tbl.HasIndex([]string{"email"}, true))
	require.True(t, tbl.HasIndex([]string{"EMAIL"}, false))
	require.True(t, tbl.HasIndex([]string{"user_id"}, false))
	require.False(t, tbl.HasIndex([]string{"user_id", "x"}, false))
	pair := &schema.TableSnapshot{Indexes: []schema.IndexSnapshot{{Columns: []string{"account_id", "provider_id"}, Unique: true}}}
	require.True(t, pair.HasIndex([]string{"provider_id", "account_id"}, true), "column order doesn't matter")
}

func TestIndexNameAndDependencyOrder(t *testing.T) {
	// Step 1: GORM's index naming, long names cut with a hash suffix
	require.Equal(t, "idx_user_email", schema.IndexName("user", "email"))
	long := schema.IndexName(strings.Repeat("t", 60), "column")
	require.Len(t, long, 64)
	require.Equal(t, long, schema.IndexName(strings.Repeat("t", 60), "column"))

	// Step 2: plugin tables come after the tables they reference, whatever the plugin order
	reg := schema.MustBuild(schema.Options{Plugins: []schema.Plugin{{ID: "p", Schema: schema.PluginSchema{
		"child":  {Fields: map[string]schema.Field{"parentId": {Type: schema.String, References: &schema.Reference{Model: "parent", Field: "id"}}}},
		"parent": {Fields: map[string]schema.Field{"userId": {Type: schema.String, References: &schema.Reference{Model: "user", Field: "id"}}}},
	}}}})
	var names []string
	for _, m := range schema.DependencyOrder(reg) {
		names = append(names, m.Name())
	}
	require.Equal(t, []string{"user", "session", "account", "verification", "parent", "child"}, names)
}
