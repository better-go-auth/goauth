package schema

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"
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
	// AddTable creates a missing table with all of its model's fields (its indexes are separate AddIndex
	// changes).
	AddTable ChangeKind = "add_table"
	// AddColumn adds a missing column to an existing table.
	AddColumn ChangeKind = "add_column"
	// AddIndex creates a missing (unique) index.
	AddIndex ChangeKind = "add_index"
)

// Change is one additive change a database needs to match a Registry.
type Change struct {
	Kind  ChangeKind
	Model string
	Table string
	// Field is the logical field (AddColumn only).
	Field ResolvedField
	// Index is the index to create (AddIndex only).
	Index IndexSpec
}

// String describes the change for logs and error messages ("add column user.loyaltyTier").
func (c Change) String() string {
	switch c.Kind {
	case AddTable:
		return fmt.Sprintf("add table %s (model %s)", c.Table, c.Model)
	case AddColumn:
		return fmt.Sprintf("add column %s.%s (field %s.%s)", c.Table, c.Field.Column, c.Model, c.Field.Name)
	case AddIndex:
		kind := "index"
		if c.Index.Unique {
			kind = "unique index"
		}
		return fmt.Sprintf("add %s %s on %s (%s)", kind, c.Index.Name, c.Table, strings.Join(c.Index.Columns, ", "))
	}
	return string(c.Kind)
}

// Plan is the list of additive changes from a Snapshot to a Registry, in the order they must be applied:
// tables (referenced tables first), then columns, then indexes. Adapters that implement Migrator turn it
// into DDL; goauth never drops or alters existing tables, columns or indexes.
type Plan struct {
	// Registry is the registry the plan was computed for (renderers need it for references and ids).
	Registry *Registry
	Changes  []Change
}

// Empty reports whether the database already matches.
func (p *Plan) Empty() bool { return p == nil || len(p.Changes) == 0 }

// Summary returns one line per change (Change.String).
func (p *Plan) Summary() []string {
	if p == nil {
		return nil
	}
	out := make([]string, len(p.Changes))
	for i, c := range p.Changes {
		out[i] = c.String()
	}
	return out
}

// IndexSpec is an index a model needs, in physical names.
type IndexSpec struct {
	// Name is the index name: Index.Name, or GORM's naming (idx_<table>_<snake field names>) so that an
	// index created here and one created by GORM's AutoMigrate are the same index.
	Name string
	// Fields are the logical fields, Columns their columns (same order).
	Fields  []string
	Columns []string
	Unique  bool
}

// IndexName returns GORM's index name for table and name parts: "idx_<table>_<parts joined by _>", dots
// replaced, cut to 64 characters with a hash suffix like gorm.io/gorm/schema.NamingStrategy.
func IndexName(table string, parts ...string) string {
	name := strings.ReplaceAll(strings.Join(append([]string{"idx", table}, parts...), "_"), ".", "_")
	const max = 64
	if utf8.RuneCountInString(name) > max {
		sum := sha1.Sum([]byte(name))
		name = name[0:max-8] + hex.EncodeToString(sum[:])[:8]
	}
	return name
}

// IndexSpecs returns every index the model needs: one per Unique or Index field (the primary key aside),
// then the multi-column Indexes.
func (m *ResolvedModel) IndexSpecs() []IndexSpec {
	var out []IndexSpec
	// Step 1: single-column indexes, named like GORM's uniqueIndex / index tags
	for _, f := range m.fields {
		if f.Name == "id" || (!f.Unique && !f.Index) {
			continue
		}
		out = append(out, IndexSpec{
			Name: IndexName(m.table, SnakeCase(f.Name)), Fields: []string{f.Name}, Columns: []string{f.Column}, Unique: f.Unique,
		})
	}
	// Step 2: multi-column indexes
	for _, idx := range m.indexes {
		spec := IndexSpec{Name: idx.Name, Unique: idx.Unique}
		var parts []string
		for _, fn := range idx.Fields {
			spec.Fields = append(spec.Fields, fn)
			spec.Columns = append(spec.Columns, m.Column(fn))
			parts = append(parts, SnakeCase(fn))
		}
		if spec.Name == "" {
			spec.Name = IndexName(m.table, parts...)
		}
		out = append(out, spec)
	}
	return out
}

// HasIndex reports whether the table has an index over the same set of columns (case-insensitive, any
// order: GORM orders composite index columns by struct field) that satisfies unique: a unique index (or
// the primary key) serves a non-unique need too.
func (t *TableSnapshot) HasIndex(columns []string, unique bool) bool {
	want := map[string]bool{}
	for _, c := range columns {
		want[strings.ToLower(c)] = true
	}
	for _, idx := range t.Indexes {
		if len(idx.Columns) != len(columns) || (unique && !idx.Unique && !idx.Primary) {
			continue
		}
		same := true
		for _, c := range idx.Columns {
			if !want[strings.ToLower(c)] {
				same = false
				break
			}
		}
		if same {
			return true
		}
	}
	return false
}

// Diff returns the tables, columns and indexes the registry declares that the snapshot lacks. Indexes are
// matched by their columns, not their names (names differ between tools and backends).
func Diff(reg *Registry, snap *Snapshot) *Plan {
	plan := &Plan{Registry: reg}
	var tables, columns, indexes []Change
	for _, m := range reg.Models() {
		// Step 1: a missing table is one change (it carries every field) plus its indexes
		t, ok := snap.Table(m.Table())
		if !ok {
			tables = append(tables, Change{Kind: AddTable, Model: m.Name(), Table: m.Table()})
			for _, idx := range m.IndexSpecs() {
				indexes = append(indexes, Change{Kind: AddIndex, Model: m.Name(), Table: m.Table(), Index: idx})
			}
			continue
		}
		// Step 2: missing columns of an existing table
		for _, f := range m.Fields() {
			if _, ok := t.Column(f.Column); !ok {
				columns = append(columns, Change{Kind: AddColumn, Model: m.Name(), Table: m.Table(), Field: f})
			}
		}
		// Step 3: missing indexes of an existing table
		for _, idx := range m.IndexSpecs() {
			if !t.HasIndex(idx.Columns, idx.Unique) {
				indexes = append(indexes, Change{Kind: AddIndex, Model: m.Name(), Table: m.Table(), Index: idx})
			}
		}
	}
	// Step 4: new tables in dependency order (a table after the tables it references), then columns, indexes
	plan.Changes = append(plan.Changes, orderTables(reg, tables)...)
	plan.Changes = append(plan.Changes, columns...)
	plan.Changes = append(plan.Changes, indexes...)
	return plan
}

// DependencyOrder returns the registry's models ordered so that every model comes after the models its
// fields reference (registry order otherwise; reference cycles keep registry order).
func DependencyOrder(reg *Registry) []*ResolvedModel {
	models := reg.Models()
	changes := make([]Change, len(models))
	for i, m := range models {
		changes[i] = Change{Kind: AddTable, Model: m.Name(), Table: m.Table()}
	}
	var out []*ResolvedModel
	for _, c := range orderTables(reg, changes) {
		m, _ := reg.Model(c.Model)
		out = append(out, m)
	}
	return out
}

// orderTables sorts AddTable changes topologically on references (stable; self references ignored).
func orderTables(reg *Registry, tables []Change) []Change {
	pending := map[string]bool{}
	for _, c := range tables {
		pending[c.Model] = true
	}
	var out []Change
	done := map[string]bool{}
	for len(out) < len(tables) {
		progressed := false
		for _, c := range tables {
			if done[c.Model] {
				continue
			}
			// Step 1: a table is ready when every model it references is not waiting to be created
			ready := true
			m, _ := reg.Model(c.Model)
			for _, f := range m.Fields() {
				if f.References != nil && f.References.Model != c.Model && pending[f.References.Model] && !done[f.References.Model] {
					ready = false
					break
				}
			}
			if ready {
				out = append(out, c)
				done[c.Model] = true
				progressed = true
			}
		}
		// Step 2: a reference cycle: keep the remaining tables in registry order
		if !progressed {
			for _, c := range tables {
				if !done[c.Model] {
					out = append(out, c)
					done[c.Model] = true
				}
			}
		}
	}
	return out
}
