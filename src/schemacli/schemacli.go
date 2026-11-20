// Package schemacli implements goauth's schema commands, for an app-side main (the schema depends on the
// app's configuration: additionalFields, renames, plugins) or the stock `src/cmd/goauth` binary:
//
//	schema  [--format sql|hcl|ent|go|prisma|mongo] [--dialect postgres|mysql|sqlite] [--out file|dir]
//	    prints the schema (default: the desired-state DDL, CREATE TABLE / CREATE INDEX). Use the SQL as an
//	    Atlas `data "external_schema"` program, for `atlas schema apply` / `atlas migrate diff`, or as sqlc
//	    input. Other formats:
//	      --format hcl [--schema name]   Atlas HCL for --dialect (schema "public", "main" on SQLite,
//	                                     "goauth" on MySQL: pass the database name with --schema)
//	      --format ent [--package schema] [--out dir]
//	                                     Ent schemas, one file per model (entsql.Skip: goauth migrates)
//	      --format go [--go-style gorm|plain] [--package models]
//	                                     Go structs; with an explicit --dialect, GORM type tags of that dialect
//	      --format prisma [--provider postgresql|mysql|sqlite|mongodb]
//	                                     schema.prisma like better-auth's generator (provider from --dialect)
//	      --format mongo                 MongoDB collections and indexes (partial unique, TTL) as JSON
//	migrate generate --dir ./migrations [--name goauth] [--database-url URL] [--dialect d] [--format plain|goose]
//	    diffs the live database against the schema and writes one timestamped, additive SQL file
//	    (<timestamp>_<name>.sql, or <timestamp>_<name>.up.sql for golang-migrate with --format golang-migrate).
//	migrate status [--database-url URL]
//	    lists what the database lacks (exit status 1 when something is missing), like Migrations.Mode verify.
//
// An app-side main is a few lines:
//
//	func main() {
//		opts := myapp.GoAuthOptions() // the same options as SetupGoAuth, Conn optional
//		if err := schemacli.Main(context.Background(), os.Args[1:], opts, os.Stdout); err != nil {
//			fmt.Fprintln(os.Stderr, err)
//			os.Exit(1)
//		}
//	}
package schemacli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/schema/render"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ErrSchemaBehind is returned by `migrate status` when the database lacks parts of the schema.
var ErrSchemaBehind = errors.New("goauth: the database is behind the schema")

// Main runs one command (args without the program name) with the app's goauth options and writes its output
// to out.
func Main(ctx context.Context, args []string, opts goauth.GoAuthOptions, out io.Writer) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "schema":
		return schemaCmd(args[1:], opts, out)
	case "migrate":
		if len(args) < 2 {
			return usage()
		}
		switch args[1] {
		case "generate":
			return generateCmd(ctx, args[2:], opts, out)
		case "status":
			return statusCmd(ctx, args[2:], opts, out)
		}
	case "help", "-h", "--help":
		_, _ = fmt.Fprint(out, Usage)
		return nil
	}
	return usage()
}

// Usage is the help text.
const Usage = `usage:
  schema [--format sql|hcl|ent|go|prisma|mongo] [--dialect postgres|mysql|sqlite] [--out file|dir]
         [--schema name] [--provider postgresql|mysql|sqlite|mongodb] [--go-style gorm|plain] [--package name]
  migrate generate --dir DIR [--name goauth] [--format plain|goose|golang-migrate] [--database-url URL] [--dialect D]
  migrate status [--database-url URL] [--dialect D]
`

func usage() error { return errors.New(Usage) }

// schemaFlags are the flags of the schema command.
type schemaFlags struct {
	format, dialect, out string
	hclSchema, provider  string
	goStyle, pkg         string
	// dialectSet reports whether --dialect was given (--format go adds GORM type tags only then).
	dialectSet bool
}

// rendered is a rendered schema: one text, or several files (file name → content) for formats like ent.
type rendered struct {
	text  string
	files map[string]string
}

// schemaCmd prints the schema in the format of --format (the desired-state SQL by default).
func schemaCmd(args []string, opts goauth.GoAuthOptions, out io.Writer) error {
	// Step 1: flags
	fs := flag.NewFlagSet("schema", flag.ContinueOnError)
	sf := schemaFlags{}
	fs.StringVar(&sf.format, "format", "sql", "sql, hcl, ent, go, prisma or mongo")
	fs.StringVar(&sf.dialect, "dialect", "postgres", "postgres, mysql or sqlite (sql, hcl, go; prisma's default provider)")
	fs.StringVar(&sf.out, "out", "", "write to this file (a directory for --format ent) instead of stdout")
	fs.StringVar(&sf.hclSchema, "schema", "", "hcl: schema name (default public, main on sqlite, goauth on mysql)")
	fs.StringVar(&sf.provider, "provider", "", "prisma: postgresql, mysql, sqlite or mongodb (default: from --dialect)")
	fs.StringVar(&sf.goStyle, "go-style", render.GoStyleGORM, "go: gorm or plain")
	fs.StringVar(&sf.pkg, "package", "", "go: package name (default models); ent: package name (default schema)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fs.Visit(func(f *flag.Flag) { sf.dialectSet = sf.dialectSet || f.Name == "dialect" })
	// Step 2: render in the requested format
	r, err := renderSchema(sf, opts)
	if err != nil {
		return err
	}
	// Step 3: write the file(s) or print
	return writeSchema(r, sf.out, out)
}

// renderSchema renders opts' schema in the format of sf. Each format is one case; a new format only needs
// its own case (and its flags in schemaCmd).
func renderSchema(sf schemaFlags, opts goauth.GoAuthOptions) (rendered, error) {
	// Step 1: the SQL dialect (sql, hcl, go) and the registry (every other format)
	if sf.format == "sql" {
		d, err := render.ParseDialect(sf.dialect)
		if err != nil {
			return rendered{}, err
		}
		sql, err := goauth.GenerateSQL(opts, d)
		return rendered{text: sql}, err
	}
	reg, err := goauth.Schema(opts)
	if err != nil {
		return rendered{}, err
	}
	// Step 2: the other formats
	switch sf.format {
	case "hcl":
		d, err := render.ParseDialect(sf.dialect)
		if err != nil {
			return rendered{}, err
		}
		text, err := render.HCLSchema(reg, d, sf.hclSchema)
		return rendered{text: text}, err
	case "go":
		goOpts := render.GoOptions{Package: sf.pkg, Style: sf.goStyle}
		// GORM type tags only for an explicit --dialect: the default keeps the structs dialect-neutral
		if sf.dialectSet {
			if goOpts.Dialect, err = render.ParseDialect(sf.dialect); err != nil {
				return rendered{}, err
			}
		}
		text, err := render.Go(reg, goOpts)
		return rendered{text: text}, err
	case "prisma":
		provider := sf.provider
		if provider == "" {
			provider = sf.dialect
		}
		text, err := render.Prisma(reg, provider)
		return rendered{text: text}, err
	case "ent":
		files, err := render.Ent(reg, render.EntOptions{Package: sf.pkg})
		return rendered{files: files}, err
	case "mongo":
		// collections and indexes (partial unique, TTL) as JSON, what the mongo adapter's migrator creates
		text, err := render.Mongo(reg)
		return rendered{text: text}, err
	}
	return rendered{}, fmt.Errorf("goauth: unknown schema --format %q (use sql, hcl, ent, go, prisma or mongo)", sf.format)
}

// writeSchema writes a rendered schema to the file (or, for several files, the directory) file, or to out
// when file is empty.
func writeSchema(r rendered, file string, out io.Writer) error {
	// Step 1: single-file formats
	if r.files == nil {
		if file != "" {
			return os.WriteFile(file, []byte(r.text), 0o644)
		}
		_, err := io.WriteString(out, r.text)
		return err
	}
	names := make([]string, 0, len(r.files))
	for name := range r.files {
		names = append(names, name)
	}
	sort.Strings(names)
	// Step 2: several files into the directory
	if file != "" {
		if err := os.MkdirAll(file, 0o755); err != nil {
			return err
		}
		for _, name := range names {
			if err := os.WriteFile(filepath.Join(file, name), []byte(r.files[name]), 0o644); err != nil {
				return err
			}
		}
		return nil
	}
	// Step 3: several files on stdout, each behind a "// ==== name ====" line
	for _, name := range names {
		if _, err := io.WriteString(out, "// ==== "+name+" ====\n"+r.files[name]); err != nil {
			return err
		}
	}
	return nil
}

// connect returns opts with Conn from --database-url when it isn't set yet.
func connect(opts goauth.GoAuthOptions, url, dialect string) (goauth.GoAuthOptions, error) {
	if opts.Conn != nil || (opts.Adapter != nil && url == "") {
		return opts, nil
	}
	if url == "" {
		url = os.Getenv("DATABASE_URL")
	}
	if url == "" {
		return opts, errors.New("goauth: no database: pass --database-url (or set DATABASE_URL), or give the options a Conn")
	}
	if dialect == "" {
		dialect = guessDialect(url)
	}
	d, err := render.ParseDialect(dialect)
	if err != nil {
		return opts, err
	}
	var dial gorm.Dialector
	switch d {
	case render.Postgres:
		dial = postgres.Open(url)
	case render.MySQL:
		dial = mysql.Open(strings.TrimPrefix(url, "mysql://"))
	default:
		dial = sqlite.Open(strings.TrimPrefix(url, "sqlite://"))
	}
	db, err := gorm.Open(dial, &gorm.Config{Logger: logger.Discard})
	if err != nil {
		return opts, fmt.Errorf("goauth: open database: %w", err)
	}
	opts.Conn = db
	return opts, nil
}

// guessDialect infers the dialect from a database URL.
func guessDialect(url string) string {
	switch {
	case strings.HasPrefix(url, "postgres://"), strings.HasPrefix(url, "postgresql://"):
		return "postgres"
	case strings.HasPrefix(url, "mysql://"), strings.Contains(url, "@tcp("):
		return "mysql"
	}
	return "sqlite"
}

// generateCmd writes one timestamped additive migration file.
func generateCmd(ctx context.Context, args []string, opts goauth.GoAuthOptions, out io.Writer) error {
	// Step 1: flags and connection
	fs := flag.NewFlagSet("migrate generate", flag.ContinueOnError)
	dir := fs.String("dir", "./migrations", "directory of the migration files")
	name := fs.String("name", "goauth", "name part of the file name")
	format := fs.String("format", "plain", "plain (<ts>_<name>.sql), goose (with -- +goose Up) or golang-migrate (<ts>_<name>.up.sql)")
	url := fs.String("database-url", "", "database to diff against (default $DATABASE_URL)")
	dialect := fs.String("dialect", "", "postgres, mysql or sqlite (default: from the URL)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	opts, err := connect(opts, *url, *dialect)
	if err != nil {
		return err
	}
	// Step 2: the additive SQL
	sql, err := goauth.GenerateMigration(ctx, opts)
	if err != nil {
		return err
	}
	if sql == "" {
		_, err = fmt.Fprintln(out, "goauth: the database is up to date; no migration written")
		return err
	}
	// Step 3: the file, in the migration tool's naming
	ts := time.Now().UTC().Format("20060102150405")
	file := fmt.Sprintf("%s_%s.sql", ts, *name)
	switch *format {
	case "plain":
	case "goose":
		sql = "-- +goose Up\n" + sql
	case "golang-migrate":
		file = fmt.Sprintf("%s_%s.up.sql", ts, *name)
	default:
		return fmt.Errorf("goauth: unknown --format %q", *format)
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(*dir, file)
	if err := os.WriteFile(path, []byte(sql), 0o644); err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, path)
	return err
}

// statusCmd lists the missing pieces.
func statusCmd(ctx context.Context, args []string, opts goauth.GoAuthOptions, out io.Writer) error {
	fs := flag.NewFlagSet("migrate status", flag.ContinueOnError)
	url := fs.String("database-url", "", "database to inspect (default $DATABASE_URL)")
	dialect := fs.String("dialect", "", "postgres, mysql or sqlite (default: from the URL)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	opts, err := connect(opts, *url, *dialect)
	if err != nil {
		return err
	}
	plan, _, err := goauth.PlanMigration(ctx, opts)
	if err != nil {
		return err
	}
	if plan.Empty() {
		_, err = fmt.Fprintln(out, "goauth: the database is up to date")
		return err
	}
	for _, line := range plan.Summary() {
		if _, err := fmt.Fprintln(out, line); err != nil {
			return err
		}
	}
	return ErrSchemaBehind
}
