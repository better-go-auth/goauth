// Package adapter is goauth's storage contract (doc 04 §4.2, better-auth's createAdapter): a small generic
// CRUD interface over plain records keyed by registry field names, with a portable Where.
//
// A backend (memory, GORM, later database/sql and MongoDB) only implements raw CRUD on physical tables and
// columns (Backend); New wraps it in the shared factory that maps fields to columns, applies defaults,
// OnUpdate values and transforms, generates IDs and normalises values (dates in UTC with millisecond
// precision, JSON and arrays as text where the backend has no native type, booleans).
package adapter

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/better-go-auth/goauth/src/schema"
)

// Record is one row/document keyed by logical field names (not columns). Values use the canonical Go types
// of schema.Normalize: string, float64, int64, bool, time.Time (UTC, ms), json.RawMessage, []string,
// []float64 or nil.
type Record = map[string]any

// Op is a Where operator (better-auth's operators).
type Op string

const (
	Eq         Op = "eq"
	Ne         Op = "ne"
	Lt         Op = "lt"
	Lte        Op = "lte"
	Gt         Op = "gt"
	Gte        Op = "gte"
	In         Op = "in"
	NotIn      Op = "not_in"
	Contains   Op = "contains"
	StartsWith Op = "starts_with"
	EndsWith   Op = "ends_with"
)

// Connector joins a condition to the others.
type Connector string

const (
	// And (the default) conditions must all match.
	And Connector = "AND"
	// Or conditions: at least one of them must match (when there are any).
	Or Connector = "OR"
)

// Where is one condition. A list of conditions matches like better-auth's adapters:
// (every And condition) AND (any Or condition).
type Where struct {
	// Field is the logical field name.
	Field string
	// Op defaults to Eq. Eq/Ne with a nil Value test IS NULL / IS NOT NULL.
	Op Op
	// Value is a single value, or a slice for In / NotIn.
	Value any
	// Connector defaults to And.
	Connector Connector
	// Insensitive compares strings case-insensitively (better-auth's mode: "insensitive").
	Insensitive bool
}

// SortBy orders FindMany results.
type SortBy struct {
	Field string
	Desc  bool
}

// Query is a FindMany request.
type Query struct {
	Where  []Where
	Sort   []SortBy
	Limit  int // 0 = no limit
	Offset int
	// Select restricts the returned fields (logical names); empty = every field.
	Select []string
}

// Adapter is the generic storage contract. Implementations come from New (factory + Backend).
type Adapter interface {
	// ID names the backend: "memory", "gorm", ...
	ID() string
	// Create inserts data (defaults, ID and OnUpdate-free values applied) and returns the stored record.
	Create(ctx context.Context, model string, data Record) (Record, error)
	// FindOne returns the first matching record, or ErrNotFound.
	FindOne(ctx context.Context, model string, where []Where, sel ...string) (Record, error)
	// FindMany returns the matching records.
	FindMany(ctx context.Context, model string, q Query) ([]Record, error)
	// Count returns the number of matching records.
	Count(ctx context.Context, model string, where []Where) (int64, error)
	// Update changes the first matching record and returns it updated, or ErrNotFound.
	Update(ctx context.Context, model string, where []Where, data Record) (Record, error)
	// UpdateMany changes every matching record and returns how many matched. A where on the old value makes
	// it a compare-and-swap (`UpdateMany(id = ? AND value = old) == 1`). On MySQL the count is the number
	// of rows actually changed.
	UpdateMany(ctx context.Context, model string, where []Where, data Record) (int64, error)
	// Delete removes the first matching record; no match is not an error.
	Delete(ctx context.Context, model string, where []Where) error
	// DeleteMany removes every matching record and returns how many were removed.
	DeleteMany(ctx context.Context, model string, where []Where) (int64, error)
	// Transaction runs fn atomically. Calls made with the ctx passed to fn join the transaction; a
	// Transaction inside fn joins the outer one.
	Transaction(ctx context.Context, fn func(ctx context.Context) error) error
}

// Migrator is an optional capability: apply the additive changes a registry needs (doc 04 §6).
type Migrator interface {
	Plan(ctx context.Context, reg *schema.Registry) (*schema.Plan, error)
	Apply(ctx context.Context, plan *schema.Plan) error
}

// Introspector is an optional capability: read the physical schema (tables, columns, indexes).
type Introspector interface {
	Inspect(ctx context.Context) (*schema.Snapshot, error)
}

// Joiner is an optional capability: load a record together with related records in one round trip.
// FindOneJoined falls back to one query per join for backends without it.
type Joiner interface {
	FindOneJoined(ctx context.Context, model string, where []Where, joins []Join) (Record, error)
}

// Join loads records of Model related to the base record: Model.RefField = base.Field.
type Join struct {
	// Model is the related model; the result is stored under this key of the base record.
	Model string
	// Field is the base record's field (e.g. "userId" on session).
	Field string
	// RefField is the related model's field (e.g. "id" on user).
	RefField string
	// Many returns every related record as []Record (one-to-many); otherwise the first one or nil.
	Many bool
	// Limit caps Many joins (0 = 100, better-auth's defaultFindManyLimit).
	Limit int
}

// ErrNotFound is returned by FindOne and Update when nothing matches.
var ErrNotFound = errors.New("adapter: record not found")

// ErrUniqueViolation matches every *UniqueError with errors.Is.
var ErrUniqueViolation = errors.New("adapter: unique constraint violated")

// UniqueError reports a write that violates a unique constraint.
type UniqueError struct {
	// Model is the logical model ("" when the backend could not tell).
	Model string
	// Fields are the logical fields of the constraint when known.
	Fields []string
	// Columns are the physical columns of the constraint when known.
	Columns []string
	// Err is the backend's original error.
	Err error
}

func (e *UniqueError) Error() string {
	what := strings.Join(e.Fields, ", ")
	if what == "" {
		what = strings.Join(e.Columns, ", ")
	}
	msg := "adapter: unique constraint violated"
	if e.Model != "" {
		msg += " on " + e.Model
	}
	if what != "" {
		msg += " (" + what + ")"
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Is makes errors.Is(err, ErrUniqueViolation) true.
func (e *UniqueError) Is(target error) bool { return target == ErrUniqueViolation }

// Unwrap returns the backend error.
func (e *UniqueError) Unwrap() error { return e.Err }

// ErrUnknownModel / ErrUnknownField report names the registry doesn't declare.
var (
	ErrUnknownModel = errors.New("adapter: unknown model")
	ErrUnknownField = errors.New("adapter: unknown field")
)

// ValueError reports a value that doesn't fit its field (wrong type, missing required value).
type ValueError struct {
	Model, Field string
	Err          error
}

func (e *ValueError) Error() string {
	return fmt.Sprintf("adapter: %s.%s: %v", e.Model, e.Field, e.Err)
}

// Unwrap returns the underlying error (e.g. a *schema.TypeError).
func (e *ValueError) Unwrap() error { return e.Err }
