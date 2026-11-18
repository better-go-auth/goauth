package adapter

import (
	"context"
	"strings"

	"github.com/better-go-auth/goauth/src/schema"
)

// Capabilities tell the factory which logical types a backend stores natively. Values of the other types
// are encoded (better-auth's supportsJSON / supportsArrays / supportsDates / supportsBooleans).
type Capabilities struct {
	// JSON: json fields are stored as Go values (json.RawMessage); otherwise as JSON text.
	JSON bool
	// Arrays: string[] / number[] are stored as Go slices; otherwise as JSON text.
	Arrays bool
	// Dates: dates are stored as time.Time; otherwise as RFC 3339 text with milliseconds.
	Dates bool
	// Booleans: booleans are stored as bool; otherwise as 1 / 0.
	Booleans bool
}

// Cond is a Where translated to physical names and storage values.
type Cond struct {
	Column      string
	Op          Op
	Value       any // a single storage value, or []any for In / NotIn
	Connector   Connector
	Insensitive bool
	// Type is the field's logical type (backends use it e.g. to compare dates or strings).
	Type schema.FieldType
}

// Order is a SortBy translated to a column.
type Order struct {
	Column string
	Desc   bool
}

// Select is a read request in physical names.
type Select struct {
	Where   []Cond
	Order   []Order
	Limit   int
	Offset  int
	Columns []string // empty = every column
}

// Row is one row keyed by column name, holding storage values.
type Row = map[string]any

// Backend is the storage-specific half of an adapter: raw CRUD on tables and columns. The factory (New)
// does everything else. Backends report unique violations as *UniqueError (Columns set when known).
type Backend interface {
	// ID names the backend ("memory", "gorm").
	ID() string
	// Capabilities returns the natively stored types.
	Capabilities() Capabilities
	// Insert adds one row.
	Insert(ctx context.Context, table string, row Row) error
	// Select returns the matching rows.
	Select(ctx context.Context, table string, q Select) ([]Row, error)
	// Count counts the matching rows.
	Count(ctx context.Context, table string, where []Cond) (int64, error)
	// Update sets columns on every matching row and returns the number of rows changed.
	Update(ctx context.Context, table string, where []Cond, set Row) (int64, error)
	// Delete removes every matching row and returns how many were removed.
	Delete(ctx context.Context, table string, where []Cond) (int64, error)
	// Transaction runs fn atomically; nested calls join the outer transaction.
	Transaction(ctx context.Context, fn func(ctx context.Context) error) error
}

// IDInserter is an optional Backend capability used when the database creates ids (schema.IDDatabase,
// schema.IDSerial): insert a row that has no id column and return the id the database generated, or nil
// when the backend can't tell (the factory then finds the row by its unique values, like better-auth's
// Kysely adapter on MySQL). serial reports auto-increment integer ids.
type IDInserter interface {
	InsertReturningID(ctx context.Context, table string, row Row, idColumn string, serial bool) (any, error)
}

// LikeEscape is the escape character of LikePattern. '!' rather than a backslash because MySQL parses a
// backslash in string literals differently from Postgres and SQLite.
const LikeEscape = '!'

// LikePattern builds an escaped SQL LIKE pattern (use with `ESCAPE '!'`) for Contains, StartsWith or
// EndsWith: the wildcards % and _ (and the escape character) in value match themselves.
func LikePattern(op Op, value string) string {
	esc := strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(value)
	switch op {
	case StartsWith:
		return esc + "%"
	case EndsWith:
		return "%" + esc
	default:
		return "%" + esc + "%"
	}
}

// Unwrapper is implemented by factory adapters; it exposes the backend behind them.
type Unwrapper interface {
	Unwrap() Backend
}

// As returns the optional capability T (Migrator, Introspector, Joiner) of a, looking at the adapter and
// then at its backend.
func As[T any](a Adapter) (T, bool) {
	if t, ok := a.(T); ok {
		return t, true
	}
	if u, ok := a.(Unwrapper); ok {
		if t, ok := u.Unwrap().(T); ok {
			return t, true
		}
	}
	var zero T
	return zero, false
}
