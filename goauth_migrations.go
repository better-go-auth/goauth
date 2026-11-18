package goauth

import (
	"context"
	"fmt"
	"strings"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/common/logger"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/migration"
	core_migration "github.com/better-go-auth/goauth/src/models/migration/core-migration"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/better-go-auth/goauth/src/schema/render"
)

// SchemaMismatchError is returned by SetupGoAuth in GoAuth.Migrations.Mode "verify" when the database
// lacks tables, columns or indexes of the schema registry.
type SchemaMismatchError struct {
	// Plan lists the missing pieces.
	Plan *schema.Plan
	// SQL creates them (additive statements for the database's dialect).
	SQL string
}

func (e *SchemaMismatchError) Error() string {
	return fmt.Sprintf("goauth: the database schema is behind goauth's schema (GoAuth.Migrations.Mode = verify); missing:\n  %s\n\n"+
		"Apply this SQL with your migration tool (or run `goauth migrate generate`):\n%s",
		strings.Join(e.Plan.Summary(), "\n  "), e.SQL)
}

// runCoreMigrations brings the database to the registry according to GoAuth.Migrations.Mode, before any
// plugin is initialized:
//
//   - auto: (1) the core GORM bootstrap, only with application-generated ids: the legacy upgrades of older
//     goauth databases (column renames and merges, dropped indexes, MySQL binary collations) and GORM
//     AutoMigrate of the core structs, so the column types of existing databases stay GORM's;
//     GoAuthOptions.Migrator replaces this step.
//     (2) the registry migrator: every missing table (plugin SchemaProvider tables, rateLimit, all core
//     tables when the database creates ids), column (additionalFields) and index. Additive only. It runs
//     again after the plugins' GORM migrators (see applyRegistry).
//   - verify: compare the registry with the database; fail with the missing pieces and their SQL.
//   - off: nothing.
//
// Third-party plugins that still migrate GORM structs (Plugin.Migrator) run after their Init, in auto mode
// only; goauth's plugins declare their tables with SchemaProvider.
func runCoreMigrations(ctx context.Context, opts GoAuthOptions, mode config.MigrationMode, reg *schema.Registry, store adapter.Adapter) error {
	if mode == config.MigrationsOff {
		return nil
	}
	mig, hasMigrator := adapter.Migrator(nil), false
	if store != nil {
		mig, hasMigrator = adapter.As[adapter.Migrator](store)
	}
	// Step 1: verify mode only compares
	if mode == config.MigrationsVerify {
		if !hasMigrator {
			return nil
		}
		plan, err := mig.Plan(ctx, reg)
		if err != nil {
			return fmt.Errorf("goauth: verify schema: %w", err)
		}
		if plan.Empty() {
			return nil
		}
		return &SchemaMismatchError{Plan: plan, SQL: planSQL(store, plan)}
	}
	// Step 2: auto mode: the core GORM bootstrap (or the configured migrator)
	var core migration.IMigrator = opts.Migrator
	if core == nil && opts.Conn != nil && !reg.IDStrategy().DatabaseGenerated() {
		core = core_migration.NewGORMAdminMigrator(opts.Conn)
	}
	if core != nil {
		if err := core.Migrate(ctx); err != nil {
			return err
		}
	}
	// Step 3: auto mode: the registry's additive changes
	return applyRegistry(ctx, reg, store)
}

// applyRegistry applies the additive changes the database needs to match reg (auto mode). SetupGoAuth
// runs it before the plugins' GORM migrators and once more after them: GORM's SQLite migrator rebuilds a
// table to add a foreign key (the organization plugin's constraint on session), which drops the table's
// indexes.
func applyRegistry(ctx context.Context, reg *schema.Registry, store adapter.Adapter) error {
	if store == nil {
		return nil
	}
	mig, ok := adapter.As[adapter.Migrator](store)
	if !ok {
		return nil
	}
	plan, err := mig.Plan(ctx, reg)
	if err != nil {
		return fmt.Errorf("goauth: plan schema migration: %w", err)
	}
	if plan.Empty() {
		return nil
	}
	if err := mig.Apply(ctx, plan); err != nil {
		return err
	}
	for _, line := range plan.Summary() {
		logger.Info("goauth: migrated schema", "change", line)
	}
	return nil
}

// planSQL renders plan for the store's dialect (a summary only when the backend has no SQL dialect).
func planSQL(store adapter.Adapter, plan *schema.Plan) string {
	type dialecter interface {
		Dialect() (render.Dialect, error)
	}
	if dd, ok := adapter.As[dialecter](store); ok {
		if d, err := dd.Dialect(); err == nil {
			if sql, err := render.PlanSQL(plan, d); err == nil {
				return sql
			}
		}
	}
	return "-- " + strings.Join(plan.Summary(), "\n-- ")
}
