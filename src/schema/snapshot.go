package schema

import (
	"strings"
)

// Snapshot is the physical schema found in a database, as returned by an adapter's Introspector.
type Snapshot struct {
	Tables []TableSnapshot
}

// TableSnapshot is one table (or collection) of a Snapshot.
type TableSnapshot struct {
	Name    string
	Columns []ColumnSnapshot
	Indexes []IndexSnapshot
}

// ColumnSnapshot is one column of a TableSnapshot.
type ColumnSnapshot struct {
	Name string
	// DatabaseType is the backend's type name (e.g. "TEXT", "varchar", "timestamptz").
	DatabaseType string
	Nullable     bool
}

// IndexSnapshot is one index of a TableSnapshot.
type IndexSnapshot struct {
	Name    string
	Columns []string
	Unique  bool
	Primary bool
}

// Table returns the table named name (compared case-insensitively, like SQL identifiers).
func (s *Snapshot) Table(name string) (*TableSnapshot, bool) {
	for i := range s.Tables {
		if strings.EqualFold(s.Tables[i].Name, name) {
			return &s.Tables[i], true
		}
	}
	return nil, false
}

// Column returns the column named name (compared case-insensitively).
func (t *TableSnapshot) Column(name string) (*ColumnSnapshot, bool) {
	for i := range t.Columns {
		if strings.EqualFold(t.Columns[i].Name, name) {
			return &t.Columns[i], true
		}
	}
	return nil, false
}

// ChangeKind is the kind of an additive schema change.
type ChangeKind string

const (
	// AddTable creates a missing table with all of its model's fields.
	AddTable ChangeKind = "add_table"
	// AddColumn adds a missing column to an existing table.
	AddColumn ChangeKind = "add_column"
)

// Change is one additive change a database needs to match a Registry.
type Change struct {
	Kind  ChangeKind
	Model string
	Table string
	// Field is the logical field (AddColumn only).
	Field ResolvedField
}

// Plan is the list of additive changes from a Snapshot to a Registry. Adapters that implement Migrator
// turn it into DDL; goauth never drops or alters existing columns.
type Plan struct {
	Changes []Change
}

// Empty reports whether the database already matches.
func (p *Plan) Empty() bool { return p == nil || len(p.Changes) == 0 }

// Diff returns the tables and columns the registry declares that the snapshot lacks. Indexes are not
// compared yet (index names differ per backend).
func Diff(reg *Registry, snap *Snapshot) *Plan {
	plan := &Plan{}
	for _, m := range reg.Models() {
		// Step 1: a missing table is one change (it carries every field)
		t, ok := snap.Table(m.Table())
		if !ok {
			plan.Changes = append(plan.Changes, Change{Kind: AddTable, Model: m.Name(), Table: m.Table()})
			continue
		}
		// Step 2: missing columns of an existing table
		for _, f := range m.Fields() {
			if _, ok := t.Column(f.Column); !ok {
				plan.Changes = append(plan.Changes, Change{Kind: AddColumn, Model: m.Name(), Table: m.Table(), Field: f})
			}
		}
	}
	return plan
}
