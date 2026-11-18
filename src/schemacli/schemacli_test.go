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
