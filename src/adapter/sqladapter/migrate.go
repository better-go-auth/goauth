package sqladapter

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/better-go-auth/goauth/src/schema/render"
)

// Inspect reads every table of the database (the current schema on Postgres, the current database on MySQL)
// with its columns and indexes (adapter.Introspector).
func (b *Backend) Inspect(ctx context.Context) (*schema.Snapshot, error) {
	var q string
	switch b.d {
	case Postgres:
		q = "SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema() AND table_type = 'BASE TABLE' ORDER BY table_name"
	case MySQL:
		q = "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE' ORDER BY table_name"
	default:
		q = "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
	}
	tables, err := b.strings(ctx, q)
	if err != nil {
		return nil, err
	}
	return b.InspectTables(ctx, tables...)
}

// InspectTables reads the given tables (those that exist) with their columns and indexes. Prefer it to
// Inspect on a shared database: it never looks at other applications' tables.
func (b *Backend) InspectTables(ctx context.Context, tables ...string) (*schema.Snapshot, error) {
	snap := &schema.Snapshot{}
	for _, name := range tables {
		// Step 1: columns (a table without columns doesn't exist)
		cols, err := b.columns(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("sqladapter: columns of %s: %w", name, err)
		}
		if len(cols) == 0 {
			continue
		}
		// Step 2: indexes
		idxs, err := b.indexes(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("sqladapter: indexes of %s: %w", name, err)
		}
		snap.Tables = append(snap.Tables, schema.TableSnapshot{Name: name, Columns: cols, Indexes: idxs})
	}
	return snap, nil
}

// strings runs a query returning one string column.
func (b *Backend) strings(ctx context.Context, q string, args ...any) ([]string, error) {
	rows, err := b.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// columns reads the columns of table.
func (b *Backend) columns(ctx context.Context, table string) ([]schema.ColumnSnapshot, error) {
	var q string
	switch b.d {
	case Postgres:
		q = "SELECT column_name, data_type, is_nullable = 'YES' FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 ORDER BY ordinal_position"
	case MySQL:
		q = "SELECT column_name, data_type, is_nullable = 'YES' FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? ORDER BY ordinal_position"
	default:
		q = `SELECT name, type, "notnull" = 0 FROM pragma_table_info(?) ORDER BY cid`
	}
	rows, err := b.db.QueryContext(ctx, q, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []schema.ColumnSnapshot
	for rows.Next() {
		var c schema.ColumnSnapshot
		if err := rows.Scan(&c.Name, &c.DatabaseType, &c.Nullable); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// postgresIndexSQL lists the indexes of one table of the current schema, constraint-backed ones (primary
// keys, UNIQUE constraints) included, columns in index order.
const postgresIndexSQL = `
SELECT ci.relname, i.indisunique, i.indisprimary, a.attname
FROM pg_index i
JOIN pg_class ct ON ct.oid = i.indrelid
JOIN pg_class ci ON ci.oid = i.indexrelid
JOIN pg_namespace n ON n.oid = ct.relnamespace
JOIN LATERAL unnest(i.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord) ON true
JOIN pg_attribute a ON a.attrelid = ct.oid AND a.attnum = k.attnum
WHERE ct.relname = $1 AND n.nspname = current_schema()
ORDER BY ci.relname, k.ord`

// mysqlIndexSQL lists the indexes of one table of the current database, columns in index order.
const mysqlIndexSQL = `
SELECT index_name, non_unique = 0, index_name = 'PRIMARY', column_name
FROM information_schema.statistics
WHERE table_schema = DATABASE() AND table_name = ?
ORDER BY index_name, seq_in_index`

// indexes reads the indexes of table, the primary key included.
func (b *Backend) indexes(ctx context.Context, table string) ([]schema.IndexSnapshot, error) {
	if b.d == SQLite {
		return b.sqliteIndexes(ctx, table)
	}
	q := postgresIndexSQL
	if b.d == MySQL {
		q = mysqlIndexSQL
	}
	rows, err := b.db.QueryContext(ctx, q, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	// Step 1: one row per index column, grouped by index in column order
	var out []schema.IndexSnapshot
	pos := map[string]int{}
	for rows.Next() {
		var name, col string
		var unique, primary bool
		if err := rows.Scan(&name, &unique, &primary, &col); err != nil {
			return nil, err
		}
		i, ok := pos[name]
		if !ok {
			i = len(out)
			pos[name] = i
			out = append(out, schema.IndexSnapshot{Name: name, Unique: unique, Primary: primary})
		}
		out[i].Columns = append(out[i].Columns, col)
	}
	return out, rows.Err()
}

// sqliteIndexes reads SQLite's index list, each index's columns and the primary key.
func (b *Backend) sqliteIndexes(ctx context.Context, table string) ([]schema.IndexSnapshot, error) {
	// Step 1: the index list
	rows, err := b.db.QueryContext(ctx, `SELECT name, "unique", origin FROM pragma_index_list(?)`, table)
	if err != nil {
		return nil, err
	}
	var out []schema.IndexSnapshot
	for rows.Next() {
		var idx schema.IndexSnapshot
		var origin string
		if err := rows.Scan(&idx.Name, &idx.Unique, &origin); err != nil {
			rows.Close()
			return nil, err
		}
		idx.Primary = origin == "pk"
		out = append(out, idx)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Step 2: the columns of each index
	for i := range out {
		cols, err := b.strings(ctx, `SELECT name FROM pragma_index_info(?) ORDER BY seqno`, out[i].Name)
		if err != nil {
			return nil, err
		}
		out[i].Columns = cols
	}
	// Step 3: an integer primary key has no index of its own
	pk, err := b.strings(ctx, `SELECT name FROM pragma_table_info(?) WHERE pk > 0 ORDER BY pk`, table)
	if err != nil {
		return nil, err
	}
	if len(pk) > 0 {
		out = append(out, schema.IndexSnapshot{Name: "PRIMARY", Columns: pk, Unique: true, Primary: true})
	}
	return out, nil
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

// Apply runs the additive DDL of plan (adapter.Migrator): CREATE TABLE, ADD COLUMN, CREATE INDEX, rendered
// by src/schema/render. It never drops or alters anything. A required field without a default can only be
// added to an empty table (*adapter.RequiredColumnError otherwise). On Postgres and SQLite the statements run
// in one transaction (MySQL commits DDL implicitly).
func (b *Backend) Apply(ctx context.Context, plan *schema.Plan) error {
	if plan.Empty() {
		return nil
	}
	// Step 1: required columns without a default need empty tables
	rce := &adapter.RequiredColumnError{}
	for _, c := range plan.Changes {
		if c.Kind != schema.AddColumn || !c.Field.Required || c.Field.HasDefault() {
			continue
		}
		var one int
		err := b.db.QueryRowContext(ctx, "SELECT 1 FROM "+b.d.Quote(c.Table)+" LIMIT 1").Scan(&one)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return fmt.Errorf("goauth migrations: rows of %s: %w", c.Table, err)
		}
		stmts, err := render.PlanStatements(&schema.Plan{Registry: plan.Registry, Changes: []schema.Change{c}}, b.d)
		if err != nil {
			return err
		}
		rce.Changes = append(rce.Changes, c)
		rce.SQL = append(rce.SQL, strings.Join(stmts, "; "))
	}
	if len(rce.Changes) > 0 {
		return rce
	}
	// Step 2: render and execute, in a transaction where DDL is transactional
	stmts, err := render.PlanStatements(plan, b.d)
	if err != nil {
		return err
	}
	run := func(ctx context.Context) error {
		for _, s := range stmts {
			if _, err := b.conn(ctx).ExecContext(ctx, s); err != nil {
				return fmt.Errorf("goauth migrations: %s: %w", s, err)
			}
		}
		return nil
	}
	if b.d == MySQL {
		return run(ctx)
	}
	return b.Transaction(ctx, run)
}
