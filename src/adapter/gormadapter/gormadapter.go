// Package gormadapter is the GORM adapter.Backend (SQLite, Postgres, MySQL). It works on tables and
// columns through db.Table(name) and map rows, so runtime fields need no Go struct, and it joins the
// ambient GORM transaction of the context (gormutil.TxKey), so goauth's writes can run inside the
// application's transaction.
package gormadapter

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/schema"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// New returns a GORM adapter for reg on db.
func New(db *gorm.DB, reg *schema.Registry, opts ...adapter.Option) adapter.Adapter {
	return adapter.New(reg, NewBackend(db), opts...)
}

// Backend is the GORM implementation of adapter.Backend.
type Backend struct {
	db *gorm.DB
}

var (
	_ adapter.Backend      = (*Backend)(nil)
	_ adapter.Introspector = (*Backend)(nil)
)

// NewBackend wraps db.
func NewBackend(db *gorm.DB) *Backend { return &Backend{db: db} }

// ID returns "gorm".
func (b *Backend) ID() string { return "gorm" }

// Capabilities: JSON and arrays are stored as JSON text (better-auth's layout on SQLite and MySQL; Postgres
// accepts the text for jsonb columns too); dates and booleans are native.
func (b *Backend) Capabilities() adapter.Capabilities {
	return adapter.Capabilities{Dates: true, Booleans: true}
}

// conn returns the transaction of ctx, or the database, bound to ctx.
func (b *Backend) conn(ctx context.Context) *gorm.DB {
	return gormutil.GetDB(ctx, b.db)
}

// dialect returns the dialector name ("sqlite", "postgres", "mysql").
func (b *Backend) dialect() string { return b.db.Dialector.Name() }

// Insert adds one row.
func (b *Backend) Insert(ctx context.Context, table string, row adapter.Row) error {
	if err := b.conn(ctx).Table(table).Create(map[string]any(row)).Error; err != nil {
		return b.translate(err)
	}
	return nil
}

// Select returns the matching rows.
func (b *Backend) Select(ctx context.Context, table string, q adapter.Select) ([]adapter.Row, error) {
	// Step 1: conditions, columns, order, paging
	db := b.conn(ctx).Table(table)
	if expr := b.where(q.Where); expr != nil {
		db = db.Where(expr)
	}
	if len(q.Columns) > 0 {
		db = db.Select(q.Columns)
	}
	for _, o := range q.Order {
		db = db.Order(clause.OrderByColumn{Column: clause.Column{Name: o.Column}, Desc: o.Desc})
	}
	if q.Limit > 0 {
		db = db.Limit(q.Limit)
	}
	if q.Offset > 0 {
		db = db.Offset(q.Offset)
	}
	// Step 2: scan into maps
	var rows []map[string]any
	if err := db.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]adapter.Row, len(rows))
	for i, r := range rows {
		out[i] = r
	}
	return out, nil
}

// Count counts the matching rows.
func (b *Backend) Count(ctx context.Context, table string, where []adapter.Cond) (int64, error) {
	db := b.conn(ctx).Table(table)
	if expr := b.where(where); expr != nil {
		db = db.Where(expr)
	}
	var n int64
	err := db.Count(&n).Error
	return n, err
}

// Update sets columns on every matching row.
func (b *Backend) Update(ctx context.Context, table string, where []adapter.Cond, set adapter.Row) (int64, error) {
	db := b.conn(ctx).Table(table)
	if expr := b.where(where); expr != nil {
		db = db.Where(expr)
	} else {
		db = db.Session(&gorm.Session{AllowGlobalUpdate: true})
	}
	res := db.Updates(map[string]any(set))
	if res.Error != nil {
		return 0, b.translate(res.Error)
	}
	return res.RowsAffected, nil
}

// Delete removes every matching row.
func (b *Backend) Delete(ctx context.Context, table string, where []adapter.Cond) (int64, error) {
	var res *gorm.DB
	if expr := b.where(where); expr != nil {
		res = b.conn(ctx).Exec("DELETE FROM ? WHERE ?", clause.Table{Name: table}, expr)
	} else {
		res = b.conn(ctx).Exec("DELETE FROM ?", clause.Table{Name: table})
	}
	if res.Error != nil {
		return 0, res.Error
	}
	return res.RowsAffected, nil
}

// Transaction runs fn in a GORM transaction stored in the context under gormutil.TxKey (the key
// gormutil.GetDB and GormTxManager use); a transaction already in ctx is joined.
func (b *Backend) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	if _, ok := ctx.Value(gormutil.TxKey).(*gorm.DB); ok {
		return fn(ctx)
	}
	return b.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(context.WithValue(ctx, gormutil.TxKey, tx))
	})
}

// where builds (all And conditions) AND (any Or condition); nil when there are none.
func (b *Backend) where(cs []adapter.Cond) clause.Expression {
	var and, or []clause.Expression
	for _, c := range cs {
		e := b.cond(c)
		if c.Connector == adapter.Or {
			or = append(or, e)
		} else {
			and = append(and, e)
		}
	}
	if len(or) > 0 {
		and = append(and, clause.Or(or...))
	}
	switch len(and) {
	case 0:
		return nil
	case 1:
		return and[0]
	}
	return clause.And(and...)
}

// alwaysTrue / alwaysFalse are the portable constant conditions.
var (
	alwaysTrue  = clause.Expr{SQL: "1 = 1"}
	alwaysFalse = clause.Expr{SQL: "1 = 0"}
)

// cond translates one condition to SQL for this dialect.
func (b *Backend) cond(c adapter.Cond) clause.Expression {
	col := clause.Column{Name: c.Column}
	// Step 1: case-insensitive comparisons lower both sides (strings only)
	lower := c.Insensitive && (c.Type == schema.String || c.Type == schema.ID)
	if lower && (c.Op == adapter.Eq || c.Op == adapter.Ne) && c.Value != nil {
		sql := "LOWER(?) = LOWER(?)"
		if c.Op == adapter.Ne {
			sql = "LOWER(?) <> LOWER(?)"
		}
		return clause.Expr{SQL: sql, Vars: []any{col, c.Value}}
	}
	switch c.Op {
	case adapter.Eq:
		return clause.Eq{Column: col, Value: c.Value}
	case adapter.Ne:
		return clause.Neq{Column: col, Value: c.Value}
	case adapter.Lt:
		return clause.Lt{Column: col, Value: c.Value}
	case adapter.Lte:
		return clause.Lte{Column: col, Value: c.Value}
	case adapter.Gt:
		return clause.Gt{Column: col, Value: c.Value}
	case adapter.Gte:
		return clause.Gte{Column: col, Value: c.Value}
	case adapter.In, adapter.NotIn:
		// Step 2: empty lists are constant (SQL has no empty IN list); NULL elements never match
		var vals []any
		for _, v := range c.Value.([]any) {
			if v != nil {
				vals = append(vals, v)
			}
		}
		if len(vals) == 0 {
			if c.Op == adapter.In {
				return alwaysFalse
			}
			return clause.Neq{Column: col, Value: nil}
		}
		if lower {
			for i, v := range vals {
				if s, ok := v.(string); ok {
					vals[i] = strings.ToLower(s)
				}
			}
			sql := "LOWER(?) IN ?"
			if c.Op == adapter.NotIn {
				sql = "LOWER(?) NOT IN ?"
			}
			return clause.Expr{SQL: sql, Vars: []any{col, vals}}
		}
		if c.Op == adapter.In {
			return clause.IN{Column: col, Values: vals}
		}
		return clause.Not(clause.IN{Column: col, Values: vals})
	case adapter.Contains, adapter.StartsWith, adapter.EndsWith:
		return b.like(col, c)
	}
	return alwaysTrue
}

// like builds an escaped LIKE condition. Case-insensitive patterns lower both sides; case-sensitive ones
// need a binary comparison on MySQL and GLOB on SQLite, whose LIKE ignores case.
func (b *Backend) like(col clause.Column, c adapter.Cond) clause.Expression {
	s := fmt.Sprint(c.Value)
	if c.Insensitive {
		return clause.Expr{SQL: "LOWER(?) LIKE LOWER(?) ESCAPE '!'", Vars: []any{col, adapter.LikePattern(c.Op, s)}}
	}
	switch b.dialect() {
	case "sqlite":
		return clause.Expr{SQL: "? GLOB ?", Vars: []any{col, globPattern(c.Op, s)}}
	case "mysql":
		return clause.Expr{SQL: "CAST(? AS BINARY) LIKE CAST(? AS BINARY) ESCAPE '!'", Vars: []any{col, adapter.LikePattern(c.Op, s)}}
	}
	return clause.Expr{SQL: "? LIKE ? ESCAPE '!'", Vars: []any{col, adapter.LikePattern(c.Op, s)}}
}

// globPattern builds a SQLite GLOB pattern: the metacharacters * ? [ in value match themselves.
func globPattern(op adapter.Op, value string) string {
	esc := strings.NewReplacer("[", "[[]", "*", "[*]", "?", "[?]").Replace(value)
	switch op {
	case adapter.StartsWith:
		return esc + "*"
	case adapter.EndsWith:
		return "*" + esc
	}
	return "*" + esc + "*"
}

// translate turns a duplicate-key error into *adapter.UniqueError, through the dialector's error
// translator (all GORM drivers implement it) or the drivers' messages.
func (b *Backend) translate(err error) error {
	dup := errors.Is(err, gorm.ErrDuplicatedKey)
	if t, ok := b.db.Dialector.(gorm.ErrorTranslator); ok && !dup {
		dup = errors.Is(t.Translate(err), gorm.ErrDuplicatedKey)
	}
	if !dup {
		msg := err.Error()
		dup = strings.Contains(msg, "UNIQUE constraint failed") || strings.Contains(msg, "SQLSTATE 23505") ||
			strings.Contains(msg, "Error 1062")
	}
	if !dup {
		return err
	}
	return &adapter.UniqueError{Columns: uniqueColumns(err.Error()), Err: err}
}

// uniqueColumns extracts the columns from SQLite's "UNIQUE constraint failed: user.email, user.x"
// message (other drivers only name the index).
func uniqueColumns(msg string) []string {
	const marker = "UNIQUE constraint failed: "
	i := strings.Index(msg, marker)
	if i < 0 {
		return nil
	}
	var cols []string
	for _, part := range strings.Split(msg[i+len(marker):], ",") {
		part = strings.TrimSpace(part)
		if dot := strings.LastIndex(part, "."); dot >= 0 {
			part = part[dot+1:]
		}
		if part != "" {
			cols = append(cols, part)
		}
	}
	return cols
}

// Inspect reads every table of the database with its columns and indexes (adapter.Introspector).
func (b *Backend) Inspect(ctx context.Context) (*schema.Snapshot, error) {
	tables, err := b.db.WithContext(ctx).Migrator().GetTables()
	if err != nil {
		return nil, err
	}
	return b.InspectTables(ctx, tables...)
}

// InspectTables reads the given tables (those that exist) with their columns and indexes. Prefer it to
// Inspect on a shared database: it never looks at other applications' tables.
func (b *Backend) InspectTables(ctx context.Context, tables ...string) (*schema.Snapshot, error) {
	m := b.db.WithContext(ctx).Migrator()
	snap := &schema.Snapshot{}
	for _, name := range tables {
		if !m.HasTable(name) {
			continue
		}
		// Step 1: columns
		t := schema.TableSnapshot{Name: name}
		cols, err := m.ColumnTypes(name)
		if err != nil {
			return nil, fmt.Errorf("gormadapter: columns of %s: %w", name, err)
		}
		for _, c := range cols {
			nullable, _ := c.Nullable()
			t.Columns = append(t.Columns, schema.ColumnSnapshot{Name: c.Name(), DatabaseType: c.DatabaseTypeName(), Nullable: nullable})
		}
		// Step 2: indexes
		idxs, err := m.GetIndexes(name)
		if err != nil {
			return nil, fmt.Errorf("gormadapter: indexes of %s: %w", name, err)
		}
		for _, idx := range idxs {
			unique, _ := idx.Unique()
			primary, _ := idx.PrimaryKey()
			t.Indexes = append(t.Indexes, schema.IndexSnapshot{Name: idx.Name(), Columns: idx.Columns(), Unique: unique, Primary: primary})
		}
		snap.Tables = append(snap.Tables, t)
	}
	return snap, nil
}
