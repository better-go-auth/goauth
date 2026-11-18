package render_test

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/schema"
	"github.com/better-go-auth/goauth/src/schema/render"
	"github.com/stretchr/testify/require"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// golden compares got with testdata/name (rewritten with -update).
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		require.NoError(t, os.WriteFile(path, []byte(got), 0o644))
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err, "missing golden file; run go test ./src/schema/render -update")
	require.Equal(t, string(want), got)
}

// pluginRegistry is camel case with an additional field, a plugin table referencing user and a
// multi-column index, the rateLimit table and the given id strategy.
func pluginRegistry(t *testing.T, ids schema.IDStrategy) *schema.Registry {
	t.Helper()
	reg, err := schema.Build(schema.Options{
		ColumnCase: schema.Camel,
		IDs:        ids,
		RateLimit:  true,
		Models: map[string]schema.ModelOptions{
			"user": {ModelName: "users", AdditionalFields: map[string]schema.Field{
				"loyaltyTier": {Type: schema.String, Required: true, Default: "bronze"},
				"score":       {Type: schema.Number},
				"tags":        {Type: schema.StringArray},
			}},
		},
		Plugins: []schema.Plugin{{ID: "notes", Schema: schema.PluginSchema{
			"note": {Fields: map[string]schema.Field{
				"userId":    {Type: schema.String, Required: true, References: &schema.Reference{Model: "user", Field: "id"}},
				"title":     {Type: schema.String, Required: true},
				"pinned":    {Type: schema.Boolean, Default: false},
				"createdAt": {Type: schema.Date, Required: true, Default: func() any { return nowForTest() }},
			}, Indexes: []schema.Index{{Fields: []string{"userId", "title"}, Unique: true}}},
		}}},
	})
	require.NoError(t, err)
	return reg
}

func TestSQL_Golden(t *testing.T) {
	cases := map[string]*schema.Registry{
		"core_snake":      schema.MustBuild(schema.Options{}),
		"plugin_camel":    pluginRegistry(t, schema.IDApplication),
		"plugin_serial":   pluginRegistry(t, schema.IDSerial),
		"plugin_database": pluginRegistry(t, schema.IDDatabase),
	}
	for name, reg := range cases {
		for _, d := range render.Dialects {
			t.Run(name+"/"+string(d), func(t *testing.T) {
				out, err := render.SQL(reg, d)
				require.NoError(t, err)
				golden(t, name+"."+string(d)+".sql", out)
			})
		}
	}
}

func TestPlanSQL_Golden(t *testing.T) {
	reg := pluginRegistry(t, schema.IDApplication)
	// Step 1: a database with every table but note, and users missing two additional fields and an index
	snap := &schema.Snapshot{}
	for _, m := range reg.Models() {
		if m.Name() == "note" {
			continue
		}
		ts := schema.TableSnapshot{Name: m.Table()}
		for _, f := range m.Fields() {
			if f.Name != "loyaltyTier" && f.Name != "score" {
				ts.Columns = append(ts.Columns, schema.ColumnSnapshot{Name: f.Column})
			}
		}
		for _, idx := range m.IndexSpecs() {
			if idx.Name != "idx_users_email" {
				ts.Indexes = append(ts.Indexes, schema.IndexSnapshot{Columns: idx.Columns, Unique: idx.Unique})
			}
		}
		snap.Tables = append(snap.Tables, ts)
	}
	plan := schema.Diff(reg, snap)
	for _, d := range render.Dialects {
		out, err := render.PlanSQL(plan, d)
		require.NoError(t, err)
		golden(t, "plan."+string(d)+".sql", out)
	}
	// Step 2: an empty plan renders nothing
	out, err := render.PlanSQL(&schema.Plan{Registry: reg}, render.Postgres)
	require.NoError(t, err)
	require.Empty(t, out)
}

func TestColumnRules(t *testing.T) {
	reg := pluginRegistry(t, schema.IDApplication)
	user, _ := reg.Model("user")
	tier, _ := user.Field("loyaltyTier")
	score, _ := user.Field("score")
	created, _ := user.Field("createdAt")
	// Step 1: NOT NULL on ADD COLUMN needs a default the dialect accepts there
	require.True(t, render.AddColumnNotNull(tier, render.SQLite))
	require.False(t, render.AddColumnNotNull(score, render.Postgres))
	require.True(t, render.AddColumnNotNull(created, render.Postgres))
	require.False(t, render.AddColumnNotNull(created, render.SQLite))
	// Step 2: dialect parsing and quoting
	for in, want := range map[string]render.Dialect{"postgresql": render.Postgres, "PG": render.Postgres, "sqlite3": render.SQLite, "mariadb": render.MySQL} {
		got, err := render.ParseDialect(in)
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
	_, err := render.ParseDialect("oracle")
	require.Error(t, err)
	_, err = render.SQL(reg, render.Dialect("oracle"))
	require.Error(t, err)
	require.Equal(t, "`a``b`", render.MySQL.Quote("a`b"))
	require.Equal(t, `"a""b"`, render.Postgres.Quote(`a"b`))
	// Step 3: serial ids make references integers
	serial := pluginRegistry(t, schema.IDSerial)
	note, _ := serial.Model("note")
	uid, _ := note.Field("userId")
	require.Equal(t, "bigint", render.ColumnType(serial, uid, render.Postgres))
	require.Equal(t, "integer", render.ColumnType(serial, uid, render.SQLite))
	require.True(t, strings.Contains(render.ColumnType(reg, tier, render.MySQL), "varchar"))
}
