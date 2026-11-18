package schema

import (
	"sort"
)

// Logical model names of better-auth's core tables.
const (
	ModelUser         = "user"
	ModelSession      = "session"
	ModelAccount      = "account"
	ModelVerification = "verification"
)

// Model is a model definition: a better-auth core table, a plugin schema entry or a new plugin table.
type Model struct {
	// ModelName overrides the table name (better-auth's modelName). Empty = the logical model name.
	ModelName string
	// Fields maps logical field names (record keys, JSON keys) to their definitions. A missing "id" field is
	// added automatically (better-auth's adapters add it the same way).
	Fields map[string]Field
	// Indexes are multi-column indexes; single-column ones use Field.Index / Field.Unique.
	Indexes []Index
}

// Index is a (possibly unique) index over several fields of one model.
type Index struct {
	// Name is the physical index name; empty lets renderers derive one.
	Name string
	// Fields are logical field names, in index order.
	Fields []string
	// Unique makes the index a unique constraint. Like SQL, rows with a NULL in any field never conflict.
	Unique bool
	// Owner is the field owner that declared the index (OwnerCore, OwnerGoAuth, a plugin ID, ...).
	Owner string
}

// PluginSchema is what a plugin contributes (better-auth's plugin `schema`): fields for existing models
// (user, session, ...) and whole new models (tables), keyed by logical model name.
type PluginSchema map[string]Model

// ResolvedField is a field of a built Registry: its definition plus its final names.
type ResolvedField struct {
	Field
	// Name is the logical field name (record key / JSON key), e.g. "emailVerified".
	Name string
	// Column is the physical column name after Fields renames, FieldName and ColumnCase, e.g. "email_verified".
	Column string
}

// ResolvedModel is a model of a built Registry: final table name and fields in a stable order. It is
// immutable; accessors return copies.
type ResolvedModel struct {
	name     string
	table    string
	fields   []ResolvedField
	byName   map[string]int
	byColumn map[string]int
	indexes  []Index
}

// Name returns the logical model name ("user").
func (m *ResolvedModel) Name() string { return m.name }

// Table returns the physical table (or collection) name.
func (m *ResolvedModel) Table() string { return m.table }

// Fields returns every field, core fields first in better-auth's order, then the others by name.
func (m *ResolvedModel) Fields() []ResolvedField {
	out := make([]ResolvedField, len(m.fields))
	copy(out, m.fields)
	return out
}

// Field returns the field with logical name name.
func (m *ResolvedModel) Field(name string) (ResolvedField, bool) {
	i, ok := m.byName[name]
	if !ok {
		return ResolvedField{}, false
	}
	return m.fields[i], true
}

// FieldByColumn returns the field stored in column.
func (m *ResolvedModel) FieldByColumn(column string) (ResolvedField, bool) {
	i, ok := m.byColumn[column]
	if !ok {
		return ResolvedField{}, false
	}
	return m.fields[i], true
}

// Has reports whether the model has a field with logical name name.
func (m *ResolvedModel) Has(name string) bool {
	_, ok := m.byName[name]
	return ok
}

// Column returns the column of field name, or "" when the model has no such field.
func (m *ResolvedModel) Column(name string) string {
	if f, ok := m.Field(name); ok {
		return f.Column
	}
	return ""
}

// Indexes returns the model's multi-column indexes.
func (m *ResolvedModel) Indexes() []Index {
	out := make([]Index, len(m.indexes))
	for i, idx := range m.indexes {
		idx.Fields = append([]string(nil), idx.Fields...)
		out[i] = idx
	}
	return out
}

// InputFields returns the fields better-auth's parseInputData looks at (getFields "input"): every field
// that is not a better-auth core field, i.e. goauth built-ins, configuration additionalFields and plugin
// fields. Core fields (name, email, ...) are handled by the endpoints themselves.
func (m *ResolvedModel) InputFields() []ResolvedField {
	var out []ResolvedField
	for _, f := range m.fields {
		if f.Owner != OwnerCore {
			out = append(out, f)
		}
	}
	return out
}

// OutputFields returns the fields that appear in API output (Returned nil or true), "id" included.
func (m *ResolvedModel) OutputFields() []ResolvedField {
	var out []ResolvedField
	for _, f := range m.fields {
		if f.IsReturned() {
			out = append(out, f)
		}
	}
	return out
}

// sortedKeys returns the keys of a field map in lexical order.
func sortedKeys(fields map[string]Field) []string {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
