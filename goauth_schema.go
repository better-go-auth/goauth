package goauth

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/adapter/gormadapter"
	"github.com/better-go-auth/goauth/src/app/repository/adapterrepo"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/models"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/better-go-auth/goauth/src/schema/render"
	"gorm.io/gorm"
	gormschema "gorm.io/gorm/schema"
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
	// Step 2: plugin schemas, in plugin order (later plugins win, like better-auth). The plugin columns of the
	// core models (role, phoneNumber, twoFactorEnabled, ...) exist only for installed plugins; the
	// hand-written GORM repositories (GORMRepositories) store models.User as a whole and keep them all
	if !opts.GORMRepositories {
		so.InstalledPlugins = pluginIDs(opts.Plugins)
	}
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

// PlanMigration compares opts' schema with the database behind opts.Conn and returns the additive changes
// it needs (missing tables, columns and indexes; nothing is ever dropped or altered).
func PlanMigration(ctx context.Context, opts GoAuthOptions) (*schema.Plan, render.Dialect, error) {
	if opts.Conn == nil {
		return nil, "", errors.New("goauth: PlanMigration needs GoAuthOptions.Conn")
	}
	reg, err := Schema(opts)
	if err != nil {
		return nil, "", err
	}
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

// GenerateMigration returns the additive SQL that brings the database behind opts.Conn to opts' schema, or
// "" when it is up to date: one migration for goose, golang-migrate or any SQL migration runner (like
// better-auth's `generate` for Kysely). Renames and drops stay human (or Atlas) decisions.
func GenerateMigration(ctx context.Context, opts GoAuthOptions) (string, error) {
	plan, d, err := PlanMigration(ctx, opts)
	if err != nil {
		return "", err
	}
	return render.PlanSQL(plan, d)
}

// Schema returns the schema registry SetupGoAuth built (see goauth.Schema).
func (g *GoAuth) Schema() *schema.Registry { return g.schema }

// Adapter returns the storage adapter over the registry (nil without Conn and adapter-based Repositories).
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
	// Step 4: plugin columns of plugins that aren't installed are neither created nor written by GORM
	return gateGORMFields(conn, reg)
}

// gormFieldState is a GORM field's original migration/write settings, restored when the field's plugin is
// installed again on the same connection.
type gormFieldState struct {
	ignoreMigration, creatable, updatable bool
	index, uniqueIndex                    string
}

var (
	gormFieldStatesMu sync.Mutex
	gormFieldStates   = map[*gormschema.Field]gormFieldState{}
)

// gateGORMFields makes GORM skip the Go fields of models.User and models.Session whose registry field is
// missing (the plugin owning the column is not installed): AutoMigrate (the core bootstrap and plugin GORM
// migrators that pull the core models in through relations) doesn't create the column or its index, and
// GORM inserts / updates don't write it. Existing columns are never dropped. The parsed models are cached
// per connection, so the change only affects conn.
func gateGORMFields(conn *gorm.DB, reg *schema.Registry) error {
	gormFieldStatesMu.Lock()
	defer gormFieldStatesMu.Unlock()
	for model, sample := range map[string]any{schema.ModelUser: &models.User{}, schema.ModelSession: &models.Session{}} {
		// Step 1: the cached GORM schema of the model
		stmt := &gorm.Statement{DB: conn}
		if err := stmt.Parse(sample); err != nil {
			return fmt.Errorf("goauth: parse %s: %w", model, err)
		}
		rm, _ := reg.Model(model)
		// Step 2: every persisted Go field follows its registry field
		ignored := map[string]bool{}
		for _, f := range stmt.Schema.Fields {
			name, ok := adapterrepo.FieldName(model, f.Name)
			if !ok || rm == nil {
				continue
			}
			installed := rm.Has(name)
			setGORMField(f, installed)
			if !installed {
				ignored[f.Name] = true
			}
		}
		// Step 3: relations through an ignored foreign key (session.impersonatedBy → user) lose their constraint
		for _, rel := range stmt.Schema.Relationships.Relations {
			skip := false
			for _, ref := range rel.References {
				if ref.ForeignKey != nil && ignored[ref.ForeignKey.Name] {
					skip = true
				}
			}
			if skip {
				setGORMField(rel.Field, false)
			} else if st, ok := gormFieldStates[rel.Field]; ok {
				rel.Field.IgnoreMigration = st.ignoreMigration
			}
		}
	}
	return nil
}

// setGORMField enables (the field's original settings) or disables (no migration, no writes, no index) a
// parsed GORM field.
func setGORMField(f *gormschema.Field, enabled bool) {
	st, saved := gormFieldStates[f]
	if !saved {
		st = gormFieldState{ignoreMigration: f.IgnoreMigration, creatable: f.Creatable, updatable: f.Updatable,
			index: f.TagSettings["INDEX"], uniqueIndex: f.TagSettings["UNIQUEINDEX"]}
		gormFieldStates[f] = st
	}
	if enabled {
		f.IgnoreMigration, f.Creatable, f.Updatable = st.ignoreMigration, st.creatable, st.updatable
		restoreTag(f, "INDEX", st.index)
		restoreTag(f, "UNIQUEINDEX", st.uniqueIndex)
		return
	}
	f.IgnoreMigration, f.Creatable, f.Updatable = true, false, false
	delete(f.TagSettings, "INDEX")
	delete(f.TagSettings, "UNIQUEINDEX")
}

// restoreTag puts back a tag setting that setGORMField removed.
func restoreTag(f *gormschema.Field, key, value string) {
	if value != "" {
		f.TagSettings[key] = value
	}
}

// checkGORMRepositories refuses configuration additionalFields with GoAuthOptions.GORMRepositories: the
// hand-written GORM repositories insert and read the Go structs only, so the values would be lost. Plugin
// SchemaProvider fields on the core models (e.g. last-login-method's lastLoginMethod) are written by updates
// (registry field names are mapped to their columns) but not inserted or read; use the default adapter
// repositories for full support.
func checkGORMRepositories(opts GoAuthOptions) error {
	var names []string
	for name, fields := range map[string]map[string]schema.Field{
		schema.ModelUser: opts.User.AdditionalFields, schema.ModelSession: opts.Session.AdditionalFields,
		schema.ModelAccount: opts.Account.AdditionalFields, schema.ModelVerification: opts.Verification.AdditionalFields,
	} {
		if len(fields) > 0 {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	return fmt.Errorf("goauth: GORMRepositories doesn't store additionalFields (configured for %s); use the default "+
		"adapter repositories", strings.Join(names, ", "))
}
