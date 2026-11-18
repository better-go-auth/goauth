package render_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/schema"
	"github.com/better-go-auth/goauth/src/schema/render"
	"github.com/stretchr/testify/require"
)

// entRequires are the modules of the compile test: Ent, and a google/uuid release newer than Ent's own
// requirement (v1.3.0) that goauth itself uses, so that the module cache usually has everything.
var entRequires = map[string]string{"entgo.io/ent": "v0.14.3", "github.com/google/uuid": "v1.6.0"}

// entGolden joins Ent's files into one golden text.
func entGolden(files map[string]string) string {
	var b strings.Builder
	for _, name := range render.EntFileNames(files) {
		b.WriteString("// ==== " + name + " ====\n")
		b.WriteString(files[name])
	}
	return b.String()
}

func TestEnt_Golden(t *testing.T) {
	for name, reg := range goldenRegistries(t) {
		t.Run(name, func(t *testing.T) {
			files, err := render.Ent(reg, render.EntOptions{})
			require.NoError(t, err)
			golden(t, name+".ent.txt", entGolden(files))
			for _, src := range files {
				typeCheckSyntax(t, src)
			}
		})
	}
}

func TestEnt_Rules(t *testing.T) {
	reg := pluginRegistry(t, schema.IDApplication)
	files, err := render.Ent(reg, render.EntOptions{Package: "entschema", Migrate: true})
	require.NoError(t, err)
	// Step 1: one file per model
	require.Equal(t, []string{"account.go", "note.go", "ratelimit.go", "session.go", "user.go", "verification.go"}, render.EntFileNames(files))
	user := files["user.go"]
	require.Contains(t, user, "package entschema\n")
	require.Contains(t, user, "type User struct {")
	require.Contains(t, user, `entsql.Annotation{Table: "users"}`)
	require.NotContains(t, user, "Skip: true")
	require.Contains(t, user, `field.String("email").StorageKey("email").Unique()`)
	require.Contains(t, user, `field.Bool("email_verified").StorageKey("emailVerified").Default(false)`)
	require.Contains(t, user, `field.Time("updated_at").StorageKey("updatedAt").Default(time.Now).UpdateDefault(time.Now)`)
	require.Contains(t, user, `field.String("image").StorageKey("image").Optional().Nillable()`)
	require.Contains(t, user, `field.Strings("tags").StorageKey("tags").Optional()`)
	require.Contains(t, user, `index.Fields("deleted_at").StorageKey("idx_users_deleted_at")`)
	require.Contains(t, files["account.go"], `index.Fields("provider_id", "account_id").Unique().StorageKey("idx_provider_account")`)
	require.Contains(t, files["session.go"], "// user_id references users(id) ON DELETE CASCADE.")
	// Step 2: entsql.Skip by default, serial ids
	files, err = render.Ent(pluginRegistry(t, schema.IDSerial), render.EntOptions{})
	require.NoError(t, err)
	require.Contains(t, files["user.go"], `entsql.Annotation{Table: "users", Skip: true}`)
	require.Contains(t, files["user.go"], `field.Int64("id")`)
	require.Contains(t, files["note.go"], `field.Int64("user_id").StorageKey("userId")`)
	_, err = render.Ent(reg, render.EntOptions{Package: "my schema"})
	require.Error(t, err)
}

// TestEnt_Compile builds the generated schemas against entgo.io/ent (skipped when Ent is not in the module
// cache), then runs Ent's code generator on them when GOAUTH_ENT_GENERATE=1 (it needs more modules: set
// GOAUTH_TEST_GOPROXY to let the go command download them).
func TestEnt_Compile(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	for name, reg := range goldenRegistries(t) {
		for _, migrate := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/migrate=%v", name, migrate), func(t *testing.T) {
				entCompile(t, reg, migrate)
			})
		}
	}
}

// entCompile builds the Ent schemas of reg in a temporary module, then, with GOAUTH_ENT_GENERATE=1, runs
// entc on them and builds the generated client.
func entCompile(t *testing.T, reg *schema.Registry, migrate bool) {
	t.Helper()
	files, err := render.Ent(reg, render.EntOptions{Migrate: migrate})
	require.NoError(t, err)
	src := map[string]string{}
	for file, code := range files {
		src["schema/"+file] = code
	}
	// Step 1: the schema package compiles
	runInTempModule(t, entRequires, src, []string{"build", "./schema"})
	if os.Getenv("GOAUTH_ENT_GENERATE") != "1" {
		return
	}
	// Step 2: entc accepts the schemas and the generated client compiles
	src["gen/main.go"] = `package main

import (
	"log"

	"entgo.io/ent/entc"
	"entgo.io/ent/entc/gen"
)

func main() {
	if err := entc.Generate("./schema", &gen.Config{Target: "./ent", Package: "goauthgen/ent"}); err != nil {
		log.Fatal(err)
	}
}
`
	runInTempModule(t, entRequires, src, []string{"run", "./gen"}, []string{"build", "./..."})
}
