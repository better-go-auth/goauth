package goauth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/adapter/gormadapter"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/models"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/better-go-auth/goauth/src/schema/render"
	"gorm.io/gorm"
)

// Schema returns the schema registry SetupGoAuth builds for opts: the core models with the configuration's
// ModelName / Fields / AdditionalFields, GoAuth.ColumnCase, TablePrefix / TableNames, the id strategy
// (Advanced.Database.IDFormat), the rateLimit table (RateLimit.Storage "database") and the schema of every
// plugin implementing plugins.SchemaProvider. It needs no database. Use it with render.SQL in an app-side
// program for Atlas (external_schema), sqlc or code generators:
//
//	reg, err := goauth.Schema(opts)
//	sql, err := render.SQL(reg, render.Postgres)
func Schema(opts GoAuthOptions) (*schema.Registry, error) {
	// Step 1: defaults, on a copy (SchemaOptions only reads naming, ids and rate-limit storage)
	opts.SetDefaults()
	so := opts.SchemaOptions()
	// Step 2: plugin schemas, in plugin order (later plugins win, like better-auth)
	for _, p := range opts.Plugins {
		if p == nil {
			continue
		}
		if sp, ok := p.(plugin.SchemaProvider); ok {
			if ps := sp.Schema(); len(ps) > 0 {
				so.Plugins = append(so.Plugins, schema.Plugin{ID: p.ID(), Schema: ps})
			}
		}
	}
	// Step 3: build and validate
	reg, err := schema.Build(so)
	if err != nil {
		return nil, fmt.Errorf("goauth: schema: %w", err)
	}
	return reg, nil
}

// GenerateSQL returns the desired-state DDL of opts' schema (CREATE TABLE / CREATE INDEX with foreign keys)
// for dialect: the input of Atlas' declarative and versioned workflows (`atlas schema apply`,
// `atlas migrate diff`, data "external_schema"), sqlc's schema folder, or a first migration file.
func GenerateSQL(opts GoAuthOptions, dialect render.Dialect) (string, error) {
	reg, err := Schema(opts)
	if err != nil {
		return "", err
	}
	return render.SQL(reg, dialect)
}

// PlanMigration compares opts' schema with the database behind opts.Conn (or opts.Adapter) and returns the
// additive changes it needs (missing tables, columns and indexes; nothing is ever dropped or altered). The
// dialect is "" for backends that aren't SQL (MongoDB: collections and indexes).
func PlanMigration(ctx context.Context, opts GoAuthOptions) (*schema.Plan, render.Dialect, error) {
	if opts.Conn == nil && opts.Adapter == nil {
		return nil, "", errors.New("goauth: PlanMigration needs GoAuthOptions.Conn or GoAuthOptions.Adapter")
	}
	reg, err := Schema(opts)
	if err != nil {
		return nil, "", err
	}
	// Step 1: without GORM, the adapter's own migrator
	if opts.Conn == nil {
		return planWithAdapter(ctx, opts.Adapter, reg)
	}
	// Step 2: the GORM backend
	b := gormadapter.NewBackend(opts.Conn)
	d, err := b.Dialect()
	if err != nil {
		return nil, "", err
	}
	plan, err := b.Plan(ctx, reg)
	if err != nil {
		return nil, "", fmt.Errorf("goauth: inspect database: %w", err)
	}
	return plan, d, nil
}

// planWithAdapter plans reg's migration through the Migrator of the adapter bound from binder.
func planWithAdapter(ctx context.Context, binder adapter.Binder, reg *schema.Registry) (*schema.Plan, render.Dialect, error) {
	a, err := binder.Bind(reg)
	if err != nil {
		return nil, "", fmt.Errorf("goauth: adapter: %w", err)
	}
	mig, ok := adapter.As[adapter.Migrator](a)
	if !ok {
		return nil, "", fmt.Errorf("goauth: the %s adapter has no migrator", a.ID())
	}
	plan, err := mig.Plan(ctx, reg)
	if err != nil {
		return nil, "", fmt.Errorf("goauth: inspect database: %w", err)
	}
	var d render.Dialect
	if dd, ok := adapter.As[sqlDialecter](a); ok {
		d, _ = dd.Dialect()
	}
	return plan, d, nil
}

// sqlDialecter is implemented by SQL backends (GORM, database/sql): their render dialect.
type sqlDialecter interface {
	Dialect() (render.Dialect, error)
}

// GenerateMigration returns the additive SQL that brings the database behind opts.Conn (or a SQL opts.Adapter) to opts' schema, or
// "" when it is up to date: one migration for goose, golang-migrate or any SQL migration runner (like
// better-auth's `generate` for Kysely). Renames and drops stay human (or Atlas) decisions.
func GenerateMigration(ctx context.Context, opts GoAuthOptions) (string, error) {
	plan, d, err := PlanMigration(ctx, opts)
	if err != nil {
		return "", err
	}
	if d == "" {
		return "", errors.New("goauth: GenerateMigration needs a SQL database (the mongo adapter's migrator creates MongoDB collections and indexes; the schema command's --format mongo prints them)")
	}
	return render.PlanSQL(plan, d)
}

// Schema returns the schema registry SetupGoAuth built (see goauth.Schema).
func (g *GoAuth) Schema() *schema.Registry { return g.schema }

// Adapter returns the storage adapter over the registry: GoAuthOptions.Adapter bound to it, the GORM adapter
// on Conn, or the adapter behind adapter-based Repositories (nil when there is none).
func (g *GoAuth) Adapter() adapter.Adapter { return g.adapter }

// syncNaming makes the GORM-based code agree with the registry: models.SetTableNames (prefix plus every
// table rename: TableNames and ModelName) and, on conn, a NamingStrategy that follows the registry's
// columns (ColumnCase, Fields renames) for the core structs and converts GORM-only plugin tables to camel
// case when the registry is camel case.
func syncNaming(reg *schema.Registry, opts GoAuthOptions, conn *gorm.DB) error {
	prefix := opts.GoAuth.TablePrefix
	// Step 1: overrides: configured TableNames (plugin models too), then the registry's resolved tables
	overrides := map[string]string{}
	for model, table := range opts.GoAuth.TableNames {
		if table != "" {
			overrides[model] = table
		}
	}
	for _, m := range reg.Models() {
		if table := strings.TrimPrefix(m.Table(), prefix); table != m.Name() {
			overrides[m.Name()] = table
		}
	}
	models.SetTableNames(prefix, overrides)
	// Step 2: the GORM naming strategy
	if conn == nil {
		return nil
	}
	conn.Config.NamingStrategy = gormutil.NewNamingStrategy(prefix, overrides, gormutil.WithRegistry(reg))
	gormutil.RegisterCallbacks(conn)
	// Step 3: GORM caches parsed models per connection; models parsed before this point keep the old names
	stmt := &gorm.Statement{DB: conn}
	if err := stmt.Parse(&models.User{}); err != nil {
		return fmt.Errorf("goauth: parse models.User: %w", err)
	}
	verified := stmt.Schema.LookUpField("EmailVerified")
	if stmt.Schema.Table != reg.Table(schema.ModelUser) || verified == nil || verified.DBName != reg.Column(schema.ModelUser, "emailVerified") {
		return fmt.Errorf("goauth: the *gorm.DB already parsed goauth's models with another naming strategy (table %q, "+
			"want %q); GORM caches parsed models per connection, so pass SetupGoAuth a connection that hasn't "+
			"used goauth's models yet (run goauth's migrations through SetupGoAuth, not before it)", stmt.Schema.Table, reg.Table(schema.ModelUser))
	}
	return nil
}

// checkDatabaseIDs refuses plugins that store their own tables through GORM structs with goauth-generated
// string ids when the database creates ids (Advanced.Database.IDFormat database / serial): their rows would
// get empty ids, and their varchar references can't point at integer ids. Plugins declaring their tables
// with SchemaProvider and using the adapter are fine.
func checkDatabaseIDs(reg *schema.Registry, list []plugin.Plugin) error {
	if !reg.IDStrategy().DatabaseGenerated() {
		return nil
	}
	var bad []string
	for _, p := range list {
		if p != nil && p.Migrator() != nil {
			bad = append(bad, p.ID())
		}
	}
	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf("goauth: Advanced.Database.IDFormat %q needs every table on the schema registry, but plugins %s "+
		"still store GORM structs with goauth-generated string ids; use another IDFormat with them", reg.IDStrategy(), strings.Join(bad, ", "))
}
