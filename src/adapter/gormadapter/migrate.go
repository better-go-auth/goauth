package gormadapter

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/better-go-auth/goauth/src/schema/render"
	"gorm.io/gorm"
)

var (
	_ adapter.Migrator   = (*Backend)(nil)
	_ adapter.IDInserter = (*Backend)(nil)
)

// Dialect returns the render dialect of the connection (postgres, mysql or sqlite).
func (b *Backend) Dialect() (render.Dialect, error) {
	return render.ParseDialect(b.dialect())
}

// Plan reads the registry's tables (and only those) and returns the additive changes the database needs:
// missing tables, columns and indexes (adapter.Migrator).
func (b *Backend) Plan(ctx context.Context, reg *schema.Registry) (*schema.Plan, error) {
	// Step 1: inspect the tables the registry declares
	var tables []string
	for _, m := range reg.Models() {
		tables = append(tables, m.Table())
	}
	snap, err := b.InspectTables(ctx, tables...)
	if err != nil {
		return nil, err
	}
	// Step 2: diff
	return schema.Diff(reg, snap), nil
}

// RequiredColumnError reports required fields without a default that would be added to tables that
// already have rows: existing rows would have no value, so goauth refuses to add them.
type RequiredColumnError struct {
	// Changes are the AddColumn changes that can't be applied.
	Changes []schema.Change
	// SQL is the statement for each change, for an operator who backfills the column themselves.
	SQL []string
}

func (e *RequiredColumnError) Error() string {
	var lines []string
	for i, c := range e.Changes {
		lines = append(lines, fmt.Sprintf("  %s.%s on table %q (would run: %s)", c.Model, c.Field.Name, c.Table, e.SQL[i]))
	}
	return "goauth migrations: these required fields have no default and their tables already have rows; give " +
		"each a Default, make it optional, or add and backfill the column yourself, then restart:\n" + strings.Join(lines, "\n")
}

// Apply runs the additive DDL of plan (adapter.Migrator): CREATE TABLE, ADD COLUMN, CREATE INDEX. It never
// drops or alters anything. A required field without a default can only be added to an empty table
// (*RequiredColumnError otherwise). On Postgres and SQLite the statements run in one transaction.
func (b *Backend) Apply(ctx context.Context, plan *schema.Plan) error {
	if plan.Empty() {
		return nil
	}
	d, err := b.Dialect()
	if err != nil {
		return err
	}
	// Step 1: required columns without a default need empty tables
	db := b.db.WithContext(ctx)
	rce := &RequiredColumnError{}
	for _, c := range plan.Changes {
		if c.Kind != schema.AddColumn || !c.Field.Required || c.Field.HasDefault() {
			continue
		}
		var n int64
		if err := db.Table(c.Table).Limit(1).Count(&n).Error; err != nil {
			return fmt.Errorf("goauth migrations: count rows of %s: %w", c.Table, err)
		}
		if n > 0 {
			stmts, err := render.PlanStatements(&schema.Plan{Registry: plan.Registry, Changes: []schema.Change{c}}, d)
			if err != nil {
				return err
			}
			rce.Changes = append(rce.Changes, c)
			rce.SQL = append(rce.SQL, strings.Join(stmts, "; "))
		}
	}
	if len(rce.Changes) > 0 {
		return rce
	}
	// Step 2: render and execute, in a transaction where DDL is transactional
	stmts, err := render.PlanStatements(plan, d)
	if err != nil {
		return err
	}
	run := func(tx *gorm.DB) error {
		for _, s := range stmts {
			if err := tx.Exec(s).Error; err != nil {
				return fmt.Errorf("goauth migrations: %s: %w", s, err)
			}
		}
		return nil
	}
	if d == render.MySQL {
		return run(db)
	}
	return db.Transaction(run)
}

// InsertReturningID inserts a row without an id and returns the id the database generated
// (adapter.IDInserter): RETURNING on Postgres and SQLite, LAST_INSERT_ID() for MySQL auto-increment ids,
// nil for other MySQL defaults (the factory then finds the row by its unique values).
func (b *Backend) InsertReturningID(ctx context.Context, table string, row adapter.Row, idColumn string, serial bool) (any, error) {
	// Step 1: INSERT INTO table (columns) VALUES (?, ...), columns in a stable order
	cols := make([]string, 0, len(row))
	for c := range row {
		cols = append(cols, c)
	}
	sort.Strings(cols)
	quoted := make([]string, len(cols))
	marks := make([]string, len(cols))
	args := make([]any, len(cols))
	for i, c := range cols {
		quoted[i] = b.quote(c)
		marks[i] = "?"
		args[i] = row[c]
	}
	insert := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", b.quote(table), strings.Join(quoted, ", "), strings.Join(marks, ", "))
	if len(cols) == 0 {
		insert = fmt.Sprintf("INSERT INTO %s DEFAULT VALUES", b.quote(table))
		if b.dialect() == "mysql" {
			insert = fmt.Sprintf("INSERT INTO %s () VALUES ()", b.quote(table))
		}
	}
	conn := b.conn(ctx)
	// Step 2: MySQL has no RETURNING; the driver reports auto-increment ids (placeholders are MySQL's own "?")
	if b.dialect() == "mysql" {
		res, err := conn.Statement.ConnPool.ExecContext(ctx, insert, args...)
		if err != nil {
			return nil, b.translate(err)
		}
		if serial {
			if id, err := res.LastInsertId(); err == nil && id > 0 {
				return id, nil
			}
		}
		return nil, nil
	}
	// Step 3: Postgres and SQLite return the new id
	var id any
	if err := conn.Raw(insert+" RETURNING "+b.quote(idColumn), args...).Row().Scan(&id); err != nil {
		return nil, b.translate(err)
	}
	if bs, ok := id.([]byte); ok {
		id = string(bs)
	}
	if id == nil {
		return nil, errors.New("gormadapter: the database returned no id")
	}
	return id, nil
}

// quote quotes an identifier for the connection's dialect.
func (b *Backend) quote(ident string) string {
	var sb strings.Builder
	b.db.Dialector.QuoteTo(&sb, ident)
	return sb.String()
}
