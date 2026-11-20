package render_test

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/schema"
	"github.com/better-go-auth/goauth/src/schema/render"
	"github.com/stretchr/testify/require"
)

func TestGo_Golden(t *testing.T) {
	for name, reg := range goldenRegistries(t) {
		for _, style := range []string{render.GoStyleGORM, render.GoStylePlain} {
			t.Run(name+"/"+style, func(t *testing.T) {
				out, err := render.Go(reg, render.GoOptions{Style: style})
				require.NoError(t, err)
				golden(t, name+"."+style+".go.txt", out)
				typeCheck(t, out)
			})
		}
	}
	// Step 1: exact GORM column types for a dialect
	out, err := render.Go(pluginRegistry(t, schema.IDApplication), render.GoOptions{Package: "authdb", Dialect: render.MySQL})
	require.NoError(t, err)
	golden(t, "plugin_camel.gorm.mysql.go.txt", out)
	typeCheck(t, out)
}

// typeCheck parses and type-checks a generated file (standard library imports only).
func typeCheck(t *testing.T, src string) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "models.go", src, parser.ParseComments)
	require.NoError(t, err)
	conf := types.Config{Importer: importer.Default()}
	_, err = conf.Check(file.Name.Name, fset, []*ast.File{file}, nil)
	require.NoError(t, err)
}

// typeCheckSyntax only parses a generated file (its imports are not available to type-check it).
func typeCheckSyntax(t *testing.T, src string) {
	t.Helper()
	_, err := parser.ParseFile(token.NewFileSet(), "schema.go", src, parser.ParseComments)
	require.NoError(t, err)
}

func TestGo_Rules(t *testing.T) {
	reg := pluginRegistry(t, schema.IDApplication)
	// Step 1: names
	for in, want := range map[string]string{"user": "User", "userId": "UserID", "lastLoginIP": "LastLoginIP", "rateLimit": "RateLimit",
		"rate_limit": "RateLimit", "callbackUrl": "CallbackURL", "ipAddress": "IPAddress", "twoFactor": "TwoFactor", "id": "ID", "2fa": "X2fa"} {
		require.Equal(t, want, render.GoName(in), in)
	}
	// Step 2: GORM tags and types
	out, err := render.Go(reg, render.GoOptions{})
	require.NoError(t, err)
	require.Contains(t, out, "package models\n")
	require.Contains(t, out, "func (User) TableName() string { return \"users\" }")
	require.Contains(t, out, "`gorm:\"column:email;size:255;not null;uniqueIndex:idx_users_email\" json:\"email\"`")
	require.Contains(t, out, "uniqueIndex:idx_provider_account,priority:1")
	require.Contains(t, out, "Image               *string")
	require.Contains(t, out, "Tags                []string")
	require.Contains(t, out, "autoCreateTime")
	// Step 3: plain style and errors
	out, err = render.Go(reg, render.GoOptions{Style: render.GoStylePlain, Package: "db"})
	require.NoError(t, err)
	require.Contains(t, out, "`db:\"emailVerified\" json:\"emailVerified\"`")
	require.NotContains(t, out, "gorm:")
	_, err = render.Go(reg, render.GoOptions{Style: "xorm"})
	require.Error(t, err)
	_, err = render.Go(reg, render.GoOptions{Package: "my-models"})
	require.Error(t, err)
	_, err = render.Go(reg, render.GoOptions{Dialect: "oracle"})
	require.Error(t, err)
	// Step 4: serial ids are int64
	out, err = render.Go(pluginRegistry(t, schema.IDSerial), render.GoOptions{})
	require.NoError(t, err)
	require.Contains(t, out, "ID                  int64")
	require.Contains(t, out, "primaryKey;autoIncrement")
}

// gormRequires are the modules of the GORM test (the versions goauth itself uses, so they are cached).
var gormRequires = map[string]string{"gorm.io/gorm": "v1.31.2", "golang.org/x/text": "v0.42.0"}

// gormProgram prints GORM's view of each struct: its table and columns, then its indexes.
const gormProgram = `package main

import (
	"fmt"
	"strings"
	"sync"

	"goauthgen/models"
	"gorm.io/gorm/schema"
)

func main() {
	for _, v := range []any{MODELS} {
		s, err := schema.Parse(v, &sync.Map{}, schema.NamingStrategy{})
		if err != nil {
			panic(err)
		}
		fmt.Println("table", s.Table, strings.Join(s.DBNames, ","))
		for _, idx := range s.ParseIndexes() {
			var cols []string
			for _, f := range idx.Fields {
				cols = append(cols, f.DBName)
			}
			fmt.Println("index", s.Table, idx.Name, idx.Class == "UNIQUE", strings.Join(cols, ","))
		}
	}
}
`

// TestGo_GORMParse lets GORM parse the generated structs (skipped when GORM is not in the module cache):
// every column and every index of render.SQL must come out of the tags, with the same names, columns and
// uniqueness.
func TestGo_GORMParse(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	for name, reg := range goldenRegistries(t) {
		for _, d := range []render.Dialect{"", render.Postgres, render.MySQL, render.SQLite} {
			t.Run(name+"/"+string(d), func(t *testing.T) {
				src, err := render.Go(reg, render.GoOptions{Dialect: d})
				require.NoError(t, err)
				// Step 1: the expected tables, columns and indexes
				var models, want []string
				for _, m := range reg.Models() {
					models = append(models, "&models."+render.GoName(m.Name())+"{}")
					var cols []string
					for _, f := range m.Fields() {
						cols = append(cols, f.Column)
					}
					want = append(want, "table "+m.Table()+" "+strings.Join(cols, ","))
					for _, idx := range m.IndexSpecs() {
						want = append(want, fmt.Sprintf("index %s %s %v %s", m.Table(), idx.Name, idx.Unique, strings.Join(idx.Columns, ",")))
					}
				}
				// Step 2: GORM's view matches
				main := strings.Replace(gormProgram, "MODELS", strings.Join(models, ", "), 1)
				out := runInTempModuleOutput(t, gormRequires, map[string]string{"models/models.go": src, "main.go": main}, "run", ".")
				require.ElementsMatch(t, want, strings.Split(strings.TrimSpace(out), "\n"))
			})
		}
	}
}
