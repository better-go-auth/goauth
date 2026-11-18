package schemacli_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/better-go-auth/goauth/src/schemacli"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestSchemaCommand(t *testing.T) {
	opts := goauth.GoAuthOptions{AuthConfig: config.AuthConfig{GoAuth: config.GoAuthConfig{ColumnCase: schema.Camel}}}
	// Step 1: stdout, every dialect
	for _, d := range []string{"postgres", "mysql", "sqlite"} {
		var out bytes.Buffer
		require.NoError(t, schemacli.Main(context.Background(), []string{"schema", "--dialect", d}, opts, &out))
		require.Contains(t, out.String(), "CREATE TABLE")
		require.Contains(t, out.String(), "emailVerified")
	}
	// Step 2: --out writes a file
	file := filepath.Join(t.TempDir(), "schema.sql")
	require.NoError(t, schemacli.Main(context.Background(), []string{"schema", "--out", file}, opts, &bytes.Buffer{}))
	b, err := os.ReadFile(file)
	require.NoError(t, err)
	require.Contains(t, string(b), `CREATE TABLE "user"`)
	// Step 3: errors
	require.Error(t, schemacli.Main(context.Background(), []string{"schema", "--dialect", "oracle"}, opts, &bytes.Buffer{}))
	require.Error(t, schemacli.Main(context.Background(), nil, opts, &bytes.Buffer{}))
	require.Error(t, schemacli.Main(context.Background(), []string{"migrate"}, opts, &bytes.Buffer{}))
}

func TestSchemaCommandFormats(t *testing.T) {
	ctx := context.Background()
	opts := goauth.GoAuthOptions{AuthConfig: config.AuthConfig{GoAuth: config.GoAuthConfig{ColumnCase: schema.Camel}}}
	run := func(args ...string) string {
		t.Helper()
		var out bytes.Buffer
		require.NoError(t, schemacli.Main(ctx, append([]string{"schema"}, args...), opts, &out))
		return out.String()
	}
	// Step 1: sql stays the default
	require.Equal(t, run(), run("--format", "sql"))
	// Step 2: Atlas HCL per dialect, with an explicit schema name
	require.Contains(t, run("--format", "hcl"), "schema \"public\" {\n}")
	require.Contains(t, run("--format", "hcl", "--dialect", "sqlite"), "schema = schema.main")
	mysql := run("--format", "hcl", "--dialect", "mysql", "--schema", "app")
	require.Contains(t, mysql, "schema = schema.app")
	require.Contains(t, mysql, `collate = "utf8mb4_bin"`)
	// Step 3: Go structs, GORM (type tags only with an explicit --dialect) or plain
	gorm := run("--format", "go")
	require.Contains(t, gorm, "package models\n")
	require.Contains(t, gorm, "func (User) TableName() string")
	require.NotContains(t, gorm, "type:")
	require.Contains(t, run("--format", "go", "--dialect", "postgres"), "type:timestamptz")
	plain := run("--format", "go", "--go-style", "plain", "--package", "authdb")
	require.Contains(t, plain, "package authdb\n")
	require.Contains(t, plain, "`db:\"emailVerified\" json:\"emailVerified\"`")
	// Step 4: Prisma, provider from --dialect or --provider
	require.Contains(t, run("--format", "prisma"), `provider = "postgresql"`)
	require.Contains(t, run("--format", "prisma", "--dialect", "mysql"), `provider = "mysql"`)
	require.Contains(t, run("--format", "prisma", "--provider", "mongodb"), `@map("_id")`)
	// Step 4b: MongoDB collections and indexes as JSON (partial unique on phoneNumber, TTL on expiresAt)
	mongo := run("--format", "mongo")
	require.Contains(t, mongo, `"partialFilterExpression"`)
	require.Contains(t, mongo, `"expireAfterSeconds": 0`)
	// Step 5: Ent, on stdout or one file per model in --out
	ent := run("--format", "ent")
	require.Contains(t, ent, "// ==== user.go ====\n")
	require.Contains(t, ent, "entsql.Annotation{Table: \"user\", Skip: true}")
	dir := filepath.Join(t.TempDir(), "ent", "schema")
	run("--format", "ent", "--out", dir, "--package", "entschema")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 4)
	user, err := os.ReadFile(filepath.Join(dir, "user.go"))
	require.NoError(t, err)
	require.Contains(t, string(user), "package entschema\n")
	// Step 6: --out for single-file formats, and errors
	file := filepath.Join(t.TempDir(), "schema.prisma")
	run("--format", "prisma", "--provider", "sqlite", "--out", file)
	b, err := os.ReadFile(file)
	require.NoError(t, err)
	require.Contains(t, string(b), `url      = "file:./dev.db"`)
	for _, args := range [][]string{
		{"--format", "xml"},
		{"--format", "hcl", "--dialect", "oracle"},
		{"--format", "prisma", "--provider", "oracle"},
		{"--format", "go", "--go-style", "xorm"},
		{"--format", "go", "--dialect", "oracle"},
		{"--format", "ent", "--package", "bad name"},
	} {
		require.Error(t, schemacli.Main(ctx, append([]string{"schema"}, args...), opts, &bytes.Buffer{}), args)
	}
}

func TestMigrateGenerateAndStatus(t *testing.T) {
	ctx := context.Background()
	dbFile := filepath.Join(t.TempDir(), "app.db")
	dir := filepath.Join(t.TempDir(), "migrations")
	opts := goauth.GoAuthOptions{}
	url := []string{"--database-url", "sqlite://" + dbFile}
	// Step 1: an empty database is behind
	var out bytes.Buffer
	err := schemacli.Main(ctx, append([]string{"migrate", "status"}, url...), opts, &out)
	require.ErrorIs(t, err, schemacli.ErrSchemaBehind)
	require.Contains(t, out.String(), "add table user")

	// Step 2: generate writes one goose file; applying it brings the database up to date
	out.Reset()
	require.NoError(t, schemacli.Main(ctx, append([]string{"migrate", "generate", "--dir", dir, "--format", "goose"}, url...), opts, &out))
	path := strings.TrimSpace(out.String())
	require.True(t, strings.HasSuffix(path, "_goauth.sql"), path)
	sql, err := os.ReadFile(path)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(sql), "-- +goose Up\n"))
	db, err := gorm.Open(sqlite.Open(dbFile), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	_, err = sqlDB.Exec(string(sql))
	require.NoError(t, err)
	out.Reset()
	require.NoError(t, schemacli.Main(ctx, append([]string{"migrate", "status"}, url...), opts, &out))
	require.Contains(t, out.String(), "up to date")

	// Step 3: nothing to generate any more
	out.Reset()
	require.NoError(t, schemacli.Main(ctx, append([]string{"migrate", "generate", "--dir", dir}, url...), opts, &out))
	require.Contains(t, out.String(), "no migration written")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}
