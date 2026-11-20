// Package sqladapter is the database/sql adapter.Backend for Postgres, MySQL and SQLite (doc 04 §5.1). It
// is driver-agnostic: the application passes a *sql.DB opened with any driver (pgx's stdlib, lib/pq,
// go-sql-driver/mysql, mattn/go-sqlite3, modernc.org/sqlite, ...), which is how Bun (bunDB.DB), sqlx
// (sqlxDB.DB), pgx (stdlib.OpenDBFromPool), sqlc and Ent (entsql) applications run goauth without GORM.
//
// Queries are built by a small internal builder (placeholders, quoting, escaped LIKE patterns, case-insensitive
// comparisons per dialect). Writes join the transaction of the context: one started by Transaction, or the
// application's own *sql.Tx passed with WithTx. The backend also implements adapter.IDInserter (database and
// serial ids), adapter.Introspector and adapter.Migrator (goauth's additive DDL from src/schema/render).
//
//	db, _ := sql.Open("pgx", os.Getenv("DATABASE_URL"))
//	auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
//		AuthConfig: cfg,
//		Adapter:    sqladapter.New(db, sqladapter.Postgres),
//	})
package sqladapter

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/better-go-auth/goauth/src/schema/render"
)

// Dialect is the SQL dialect of the database (render's dialects).
type Dialect = render.Dialect

// The supported dialects.
const (
	Postgres = render.Postgres
	MySQL    = render.MySQL
	SQLite   = render.SQLite
)

// Backend is the database/sql implementation of adapter.Backend.
type Backend struct {
	db *sql.DB
	d  Dialect
}

var (
	_ adapter.Backend      = (*Backend)(nil)
	_ adapter.Binder       = (*Backend)(nil)
	_ adapter.IDInserter   = (*Backend)(nil)
	_ adapter.Introspector = (*Backend)(nil)
	_ adapter.Migrator     = (*Backend)(nil)
)

// New returns a backend on db for dialect d. An empty dialect is detected from db's driver (DetectDialect)
// and New panics when it can't be; pass the dialect explicitly for drivers it doesn't know.
//
// Bind it to a registry (GoAuthOptions.Adapter does this) or use NewAdapter.
func New(db *sql.DB, d Dialect) *Backend {
	if d == "" {
		detected, err := DetectDialect(db)
		if err != nil {
			panic(err)
		}
		d = detected
	}
	parsed, err := render.ParseDialect(string(d))
	if err != nil {
		panic(fmt.Errorf("sqladapter: %w", err))
	}
	return &Backend{db: db, d: parsed}
}

// NewAdapter returns an adapter for reg on db (New + Bind).
func NewAdapter(db *sql.DB, d Dialect, reg *schema.Registry, opts ...adapter.Option) adapter.Adapter {
	return adapter.New(reg, New(db, d), opts...)
}

// DetectDialect infers the dialect from the type of db's driver: pgx's stdlib and lib/pq are Postgres,
// go-sql-driver/mysql is MySQL, mattn/go-sqlite3 and modernc.org/sqlite (also through glebarez) are SQLite.
func DetectDialect(db *sql.DB) (Dialect, error) {
	t := reflect.TypeOf(db.Driver())
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	pkg := t.PkgPath()
	switch {
	case strings.Contains(pkg, "pgx"), strings.HasSuffix(pkg, "lib/pq"):
		return Postgres, nil
	case strings.Contains(pkg, "mysql"):
		return MySQL, nil
	case strings.Contains(pkg, "sqlite"):
		return SQLite, nil
	}
	return "", fmt.Errorf("sqladapter: can't tell the dialect of driver %s.%s; pass it to sqladapter.New", pkg, t.Name())
}

// Bind returns the adapter for reg on this backend (adapter.Binder).
func (b *Backend) Bind(reg *schema.Registry, opts ...adapter.Option) (adapter.Adapter, error) {
	return adapter.New(reg, b, opts...), nil
}

// DB returns the database.
func (b *Backend) DB() *sql.DB { return b.db }

// ID returns "sql".
func (b *Backend) ID() string { return "sql" }

// Dialect returns the backend's dialect (it never fails; the error matches the GORM backend's method).
func (b *Backend) Dialect() (render.Dialect, error) { return b.d, nil }

// Capabilities: JSON and arrays are JSON text everywhere (jsonb / json columns accept it); Postgres and
// MySQL store dates and booleans natively. SQLite gets ISO 8601 date strings with milliseconds (better-auth's
// layout there, and ordered correctly as text whatever the driver) and 1 / 0 booleans.
func (b *Backend) Capabilities() adapter.Capabilities {
	if b.d == SQLite {
		return adapter.Capabilities{}
	}
	return adapter.Capabilities{Dates: true, Booleans: true}
}

// ─── transactions ────────────────────────────────────────────────────────────

type txKey struct{}

// WithTx returns a context whose goauth writes run in tx: pass the *sql.Tx of the application's own
// transaction (Bun's bun.Tx.Tx, sqlx's *sqlx.Tx.Tx, an Ent driver's transaction, ...) to commit goauth's
// writes together with the application's. The backend never commits or rolls back tx.
func WithTx(ctx context.Context, tx *sql.Tx) context.Context {
	return context.WithValue(ctx, txKey{}, tx)
}

// TxFrom returns the transaction of ctx (WithTx or Transaction), if any.
func TxFrom(ctx context.Context) (*sql.Tx, bool) {
	tx, ok := ctx.Value(txKey{}).(*sql.Tx)
	return tx, ok && tx != nil
}

// querier is what *sql.DB and *sql.Tx have in common.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// conn returns the transaction of ctx, or the database.
func (b *Backend) conn(ctx context.Context) querier {
	if tx, ok := TxFrom(ctx); ok {
		return tx
	}
	return b.db
}

// Transaction runs fn in a database transaction stored in the context (see WithTx). A transaction already
// in ctx is joined: fn runs in it and the outer owner commits or rolls back.
func (b *Backend) Transaction(ctx context.Context, fn func(ctx context.Context) error) (err error) {
	if _, ok := TxFrom(ctx); ok {
		return fn(ctx)
	}
	// Step 1: begin
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	// Step 2: roll back on error or panic, commit otherwise
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err = fn(WithTx(ctx, tx)); err != nil {
		return err
	}
	return tx.Commit()
}

// ─── CRUD ────────────────────────────────────────────────────────────────────

// Insert adds one row.
func (b *Backend) Insert(ctx context.Context, table string, row adapter.Row) error {
	q, args := b.insertSQL(table, row)
	if _, err := b.conn(ctx).ExecContext(ctx, q, args...); err != nil {
		return translate(err)
	}
	return nil
}

// insertSQL renders INSERT INTO table (columns) VALUES (...), columns in a stable order.
func (b *Backend) insertSQL(table string, row adapter.Row) (string, []any) {
	cols := make([]string, 0, len(row))
	for c := range row {
		cols = append(cols, c)
	}
	sort.Strings(cols)
	if len(cols) == 0 {
		if b.d == MySQL {
			return fmt.Sprintf("INSERT INTO %s () VALUES ()", b.d.Quote(table)), nil
		}
		return fmt.Sprintf("INSERT INTO %s DEFAULT VALUES", b.d.Quote(table)), nil
	}
	qb := b.builder()
	quoted := make([]string, len(cols))
	marks := make([]string, len(cols))
	for i, c := range cols {
		quoted[i] = b.d.Quote(c)
		marks[i] = qb.arg(row[c])
	}
	return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", b.d.Quote(table), strings.Join(quoted, ", "), strings.Join(marks, ", ")), qb.args
}

// Select returns the matching rows.
func (b *Backend) Select(ctx context.Context, table string, q adapter.Select) ([]adapter.Row, error) {
	// Step 1: SELECT columns FROM table WHERE … ORDER BY … LIMIT … OFFSET …
	qb := b.builder()
	cols := "*"
	if len(q.Columns) > 0 {
		quoted := make([]string, len(q.Columns))
		for i, c := range q.Columns {
			quoted[i] = b.d.Quote(c)
		}
		cols = strings.Join(quoted, ", ")
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "SELECT %s FROM %s", cols, b.d.Quote(table))
	if w := qb.where(q.Where); w != "" {
		sb.WriteString(" WHERE " + w)
	}
	if len(q.Order) > 0 {
		parts := make([]string, len(q.Order))
		for i, o := range q.Order {
			parts[i] = b.d.Quote(o.Column)
			if o.Desc {
				parts[i] += " DESC"
			} else {
				parts[i] += " ASC"
			}
		}
		sb.WriteString(" ORDER BY " + strings.Join(parts, ", "))
	}
	sb.WriteString(b.limitOffset(q.Limit, q.Offset))
	// Step 2: run and scan every column into a map
	rows, err := b.conn(ctx).QueryContext(ctx, sb.String(), qb.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	names, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out []adapter.Row
	for rows.Next() {
		vals := make([]any, len(names))
		ptrs := make([]any, len(names))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make(adapter.Row, len(names))
		for i, n := range names {
			// drivers reuse []byte buffers between rows: copy them
			if bs, ok := vals[i].([]byte); ok {
				vals[i] = string(bs)
			}
			row[n] = vals[i]
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// limitOffset renders LIMIT / OFFSET (MySQL and SQLite need a LIMIT to take an OFFSET).
func (b *Backend) limitOffset(limit, offset int) string {
	var s string
	switch {
	case limit > 0:
		s = fmt.Sprintf(" LIMIT %d", limit)
	case offset > 0 && b.d == MySQL:
		s = " LIMIT 18446744073709551615"
	case offset > 0 && b.d == SQLite:
		s = " LIMIT -1"
	}
	if offset > 0 {
		s += fmt.Sprintf(" OFFSET %d", offset)
	}
	return s
}

// Count counts the matching rows.
func (b *Backend) Count(ctx context.Context, table string, where []adapter.Cond) (int64, error) {
	qb := b.builder()
	q := "SELECT COUNT(*) FROM " + b.d.Quote(table)
	if w := qb.where(where); w != "" {
		q += " WHERE " + w
	}
	var n int64
	err := b.conn(ctx).QueryRowContext(ctx, q, qb.args...).Scan(&n)
	return n, err
}

// Update sets columns on every matching row and returns the number of rows changed (MySQL counts only
// rows whose values actually changed).
func (b *Backend) Update(ctx context.Context, table string, where []adapter.Cond, set adapter.Row) (int64, error) {
	// Step 1: SET in a stable column order, then WHERE
	cols := make([]string, 0, len(set))
	for c := range set {
		cols = append(cols, c)
	}
	sort.Strings(cols)
	qb := b.builder()
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = b.d.Quote(c) + " = " + qb.arg(set[c])
	}
	q := fmt.Sprintf("UPDATE %s SET %s", b.d.Quote(table), strings.Join(parts, ", "))
	if w := qb.where(where); w != "" {
		q += " WHERE " + w
	}
	// Step 2: run
	res, err := b.conn(ctx).ExecContext(ctx, q, qb.args...)
	if err != nil {
		return 0, translate(err)
	}
	return res.RowsAffected()
}

// Delete removes every matching row and returns how many were removed.
func (b *Backend) Delete(ctx context.Context, table string, where []adapter.Cond) (int64, error) {
	qb := b.builder()
	q := "DELETE FROM " + b.d.Quote(table)
	if w := qb.where(where); w != "" {
		q += " WHERE " + w
	}
	res, err := b.conn(ctx).ExecContext(ctx, q, qb.args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// InsertReturningID inserts a row without an id and returns the id the database generated
// (adapter.IDInserter): RETURNING on Postgres and SQLite, LastInsertId for MySQL auto-increment ids, nil for
// other MySQL defaults (the factory then finds the row by its unique values).
func (b *Backend) InsertReturningID(ctx context.Context, table string, row adapter.Row, idColumn string, serial bool) (any, error) {
	q, args := b.insertSQL(table, row)
	// Step 1: MySQL has no RETURNING; the driver reports auto-increment ids
	if b.d == MySQL {
		res, err := b.conn(ctx).ExecContext(ctx, q, args...)
		if err != nil {
			return nil, translate(err)
		}
		if serial {
			if id, err := res.LastInsertId(); err == nil && id > 0 {
				return id, nil
			}
		}
		return nil, nil
	}
	// Step 2: Postgres and SQLite return the new id
	var id any
	if err := b.conn(ctx).QueryRowContext(ctx, q+" RETURNING "+b.d.Quote(idColumn), args...).Scan(&id); err != nil {
		return nil, translate(err)
	}
	if bs, ok := id.([]byte); ok {
		id = string(bs)
	}
	if id == nil {
		return nil, errors.New("sqladapter: the database returned no id")
	}
	return id, nil
}

// ─── errors ──────────────────────────────────────────────────────────────────

// translate turns a duplicate-key error of any common driver into *adapter.UniqueError: SQLSTATE 23505
// (pgx, lib/pq), MySQL error 1062, SQLite's "UNIQUE constraint failed" (mattn and modernc).
func translate(err error) error {
	if err == nil || !IsUniqueViolation(err) {
		return err
	}
	return &adapter.UniqueError{Columns: uniqueColumns(err), Err: err}
}

// IsUniqueViolation reports whether err is a unique-constraint violation from a Postgres, MySQL or SQLite
// driver.
func IsUniqueViolation(err error) bool {
	// Step 1: drivers exposing the SQLSTATE (pgx's *pgconn.PgError, lib/pq's *pq.Error)
	var st interface{ SQLState() string }
	if errors.As(err, &st) && st.SQLState() == "23505" {
		return true
	}
	// Step 2: the drivers' messages
	msg := err.Error()
	for _, m := range []string{"SQLSTATE 23505", "duplicate key value violates unique constraint", "Error 1062", "Duplicate entry", "UNIQUE constraint failed"} {
		if strings.Contains(msg, m) {
			return true
		}
	}
	return false
}

// uniqueColumns extracts the constraint's columns: SQLite's "UNIQUE constraint failed: t.a, t.b" message
// or the Postgres error's Detail "Key (a, b)=(…) already exists." (pgx and lib/pq both have a Detail field).
// MySQL only names the index.
func uniqueColumns(err error) []string {
	// Step 1: SQLite
	msg := err.Error()
	const marker = "UNIQUE constraint failed: "
	if i := strings.Index(msg, marker); i >= 0 {
		var cols []string
		rest := msg[i+len(marker):]
		if j := strings.IndexAny(rest, "()\n"); j >= 0 {
			rest = rest[:j]
		}
		for _, part := range strings.Split(rest, ",") {
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
	// Step 2: Postgres Detail
	detail := ""
	for e := err; e != nil; e = errors.Unwrap(e) {
		rv := reflect.ValueOf(e)
		if rv.Kind() == reflect.Pointer && !rv.IsNil() && rv.Elem().Kind() == reflect.Struct {
			if f := rv.Elem().FieldByName("Detail"); f.IsValid() && f.Kind() == reflect.String {
				detail = f.String()
				break
			}
		}
	}
	if !strings.HasPrefix(detail, "Key (") {
		return nil
	}
	end := strings.Index(detail, ")=")
	if end < 0 {
		return nil
	}
	var cols []string
	for _, c := range strings.Split(detail[len("Key ("):end], ",") {
		cols = append(cols, strings.Trim(strings.TrimSpace(c), `"`))
	}
	return cols
}
