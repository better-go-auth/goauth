package render_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/schema"
	"github.com/better-go-auth/goauth/src/schema/render"
	"github.com/stretchr/testify/require"
)

// goldenRegistries are the registries every renderer is checked against.
func goldenRegistries(t *testing.T) map[string]*schema.Registry {
	t.Helper()
	return map[string]*schema.Registry{
		"core_snake":      schema.MustBuild(schema.Options{}),
		"plugin_camel":    pluginRegistry(t, schema.IDApplication),
		"plugin_serial":   pluginRegistry(t, schema.IDSerial),
		"plugin_database": pluginRegistry(t, schema.IDDatabase),
	}
}

func TestHCL_Golden(t *testing.T) {
	for name, reg := range goldenRegistries(t) {
		for _, d := range render.Dialects {
			t.Run(name+"/"+string(d), func(t *testing.T) {
				out, err := render.HCL(reg, d)
				require.NoError(t, err)
				golden(t, name+"."+string(d)+".hcl", out)
			})
		}
	}
	// Step 1: an explicit schema name and an unknown dialect
	out, err := render.HCLSchema(schema.MustBuild(schema.Options{}), render.MySQL, "app")
	require.NoError(t, err)
	require.Contains(t, out, "schema \"app\" {\n}")
	require.Contains(t, out, "schema = schema.app")
	_, err = render.HCL(schema.MustBuild(schema.Options{}), render.Dialect("oracle"))
	require.Error(t, err)
	// Step 2: names that are not HCL identifiers are referenced with brackets
	out, err = render.HCL(schema.MustBuild(schema.Options{Models: map[string]schema.ModelOptions{
		"user": {ModelName: "app users", Fields: map[string]string{"email": "e mail"}},
	}}), render.Postgres)
	require.NoError(t, err)
	require.Contains(t, out, `columns = [column["e mail"]]`)
	require.Contains(t, out, `ref_columns = [table["app users"].column.id]`)
}

// atlasDevURLs are the dev databases Atlas validates the HCL against: SQLite in memory always, Postgres and
// MySQL when ATLAS_DEV_POSTGRES_URL / ATLAS_DEV_MYSQL_URL are set (e.g. "docker://postgres/16/dev",
// "docker://mysql/8/dev" or a scratch database URL).
func atlasDevURLs() map[render.Dialect]string {
	urls := map[render.Dialect]string{render.SQLite: "sqlite://dev?mode=memory"}
	if u := os.Getenv("ATLAS_DEV_POSTGRES_URL"); u != "" {
		urls[render.Postgres] = u
	}
	if u := os.Getenv("ATLAS_DEV_MYSQL_URL"); u != "" {
		urls[render.MySQL] = u
	}
	return urls
}

// TestHCL_Atlas loads the HCL with the atlas binary (skipped when atlas is not installed) and checks that
// it describes the same schema as render.SQL (`atlas schema diff` between the two finds no changes).
func TestHCL_Atlas(t *testing.T) {
	atlas, err := exec.LookPath("atlas")
	if err != nil {
		t.Skip("atlas is not in PATH")
	}
	regs := goldenRegistries(t)
	// a table and a column that are not HCL identifiers: user.email is referenced by its unique index
	regs["quoted"] = schema.MustBuild(schema.Options{TablePrefix: "my-", Models: map[string]schema.ModelOptions{
		"user": {Fields: map[string]string{"email": "e mail"}},
	}})
	for d, dev := range atlasDevURLs() {
		for name, reg := range regs {
			t.Run(name+"/"+string(d), func(t *testing.T) {
				dir := t.TempDir()
				// Step 1: write both renderings; MySQL's HCL names the dev database's schema
				schemaName := ""
				if d == render.MySQL {
					schemaName = devSchema(dev)
				}
				hcl, err := render.HCLSchema(reg, d, schemaName)
				require.NoError(t, err)
				sql, err := render.SQL(reg, d)
				require.NoError(t, err)
				hclFile, sqlFile := filepath.Join(dir, "schema.hcl"), filepath.Join(dir, "schema.sql")
				require.NoError(t, os.WriteFile(hclFile, []byte(hcl), 0o644))
				require.NoError(t, os.WriteFile(sqlFile, []byte(sql), 0o644))
				// Step 2: atlas loads the HCL
				out, err := exec.Command(atlas, "schema", "inspect", "--url", "file://"+hclFile, "--dev-url", dev, "--format", "{{ sql . }}").CombinedOutput()
				require.NoError(t, err, string(out))
				require.Contains(t, string(out), "CREATE TABLE")
				// Step 3: the HCL and the SQL are the same schema
				out, err = exec.Command(atlas, "schema", "diff", "--from", "file://"+sqlFile, "--to", "file://"+hclFile, "--dev-url", dev).CombinedOutput()
				require.NoError(t, err, string(out))
				require.Contains(t, string(out), "Schemas are synced", string(out))
			})
		}
	}
}

// devSchema returns the database name of a schema-bound dev URL ("docker://mysql/8/dev" → "dev").
func devSchema(url string) string {
	if i := strings.Index(url, "?"); i >= 0 {
		url = url[:i]
	}
	return url[strings.LastIndex(url, "/")+1:]
}
