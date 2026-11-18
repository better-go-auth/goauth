// Package schema is goauth's logical, storage-neutral database schema: better-auth's `getAuthTables` plus
// `additionalFields`, plugin `schema`, `modelName` / `fields` renames and goauth's own columns.
//
// One immutable Registry drives input parsing (ParseInput), output filtering (ParseOutput, BuildOutput),
// table/column names and, through src/adapter, every storage backend. The package must never import GORM
// or a database driver: adapters and renderers turn its logical types into physical ones.
package schema

import (
	"fmt"
)

// FieldType is a logical column type (better-auth's DBFieldType plus "integer" and "id").
type FieldType string

const (
	// String is better-auth's "string" (text / varchar).
	String FieldType = "string"
	// Number is better-auth's "number"; values are float64 in Go (JavaScript doubles).
	Number FieldType = "number"
	// Integer is a whole number (int64 in Go); better-auth's "number" with `bigint: true`.
	Integer FieldType = "integer"
	// Boolean is better-auth's "boolean".
	Boolean FieldType = "boolean"
	// Date is better-auth's "date"; values are time.Time in UTC with millisecond precision.
	Date FieldType = "date"
	// JSON is better-auth's "json"; values are json.RawMessage in Go.
	JSON FieldType = "json"
	// StringArray is better-auth's "string[]"; values are []string in Go.
	StringArray FieldType = "string[]"
	// NumberArray is better-auth's "number[]"; values are []float64 in Go.
	NumberArray FieldType = "number[]"
	// ID is the primary key (and only the primary key); values are strings in Go.
	ID FieldType = "id"
)

// valid reports whether t is one of the logical types above.
func (t FieldType) valid() bool {
	switch t {
	case String, Number, Integer, Boolean, Date, JSON, StringArray, NumberArray, ID:
		return true
	}
	return false
}

// OnDelete is the referential action of a Reference (better-auth's references.onDelete).
type OnDelete string

const (
	Cascade    OnDelete = "cascade"
	Restrict   OnDelete = "restrict"
	NoAction   OnDelete = "no action"
	SetNull    OnDelete = "set null"
	SetDefault OnDelete = "set default"
)

// Reference points a field at another model's field (better-auth's references), e.g. session.userId → user.id.
type Reference struct {
	// Model is the logical model name ("user"), not the table name.
	Model string
	// Field is the logical field name on Model ("id").
	Field string
	// OnDelete defaults to Cascade (better-auth's default) when empty.
	OnDelete OnDelete
}

// Owners of a field. Plugin-owned fields carry the plugin ID instead (e.g. "admin", "phone-number").
const (
	// OwnerCore marks better-auth's own core fields (user.name, session.token, ...).
	OwnerCore = "core"
	// OwnerGoAuth marks goauth's built-in columns that better-auth doesn't have (user.firstName, ...).
	OwnerGoAuth = "goauth"
	// OwnerConfig marks fields declared through the AdditionalFields configuration.
	OwnerConfig = "config"
)

// Field mirrors better-auth's DBFieldAttribute. The zero value of every flag is better-auth's default,
// except Input/Returned which are pointers so that nil means true.
type Field struct {
	// Type is the logical type. Required.
	Type FieldType
	// Enum restricts a String field to these values (better-auth's enum array type).
	Enum []string
	// Required makes the field mandatory on create (better-auth's `required`).
	Required bool
	// Default is used on create when the value is missing: a value, or a func() any called each time.
	Default any
	// Input reports whether clients may set the field (nil = true). input:false fields with a value are
	// rejected with FIELD_NOT_ALLOWED unless they have a Default.
	Input *bool
	// Returned reports whether the field is included in API output (nil = true).
	Returned *bool
	// Unique adds a unique constraint. A unique field that is not Required is nullable: rows without a
	// value never conflict (see IsNullableUnique).
	Unique bool
	// Index adds a (non-unique) index.
	Index bool
	// Sortable marks the field as usable for sorting/searching in list endpoints (varchar instead of text).
	Sortable bool
	// FieldName is the physical column name. It is used as is (ColumnCase does not apply).
	FieldName string
	// References makes the field a foreign key.
	References *Reference
	// Validate checks (and may convert) an input value; an error becomes 400 VALIDATION_ERROR with the
	// error's message (better-auth's validator.input).
	Validate func(v any) (any, error)
	// TransformIn converts a value before it is stored (better-auth's transform.input). Like better-auth it
	// runs in ParseInput and again in the adapter, so it must be idempotent.
	TransformIn func(v any) any
	// TransformOut converts a stored value when it is read (better-auth's transform.output).
	TransformOut func(v any) any
	// OnUpdate returns the value written on every update that doesn't set the field (e.g. updatedAt).
	OnUpdate func() any
	// Owner is OwnerCore, OwnerGoAuth, OwnerConfig or a plugin ID. Build sets it for configuration and
	// plugin fields; it is informational for callers.
	Owner string
}

// Bool returns a pointer to b, for Field.Input and Field.Returned.
func Bool(b bool) *bool { return &b }

// IsInput reports whether clients may set the field (Input nil or true).
func (f Field) IsInput() bool { return f.Input == nil || *f.Input }

// IsReturned reports whether the field is part of API output (Returned nil or true).
func (f Field) IsReturned() bool { return f.Returned == nil || *f.Returned }

// IsNullableUnique reports whether the field is unique but may be missing. SQL unique indexes already
// ignore NULLs; document stores (MongoDB) need a partial index for these fields.
func (f Field) IsNullableUnique() bool { return f.Unique && !f.Required }

// HasDefault reports whether the field has a Default.
func (f Field) HasDefault() bool { return f.Default != nil }

// DefaultValue returns the field's default, calling it when it is a func() any.
func (f Field) DefaultValue() any {
	switch d := f.Default.(type) {
	case func() any:
		return d()
	default:
		return d
	}
}

// validate checks the attributes that can be checked without the rest of the schema.
func (f Field) validate(model, name string) error {
	// Step 1: the type must be a known logical type
	if !f.Type.valid() {
		return fmt.Errorf("schema: %s.%s: invalid type %q", model, name, f.Type)
	}
	// Step 2: enum values only make sense on strings
	if len(f.Enum) > 0 && f.Type != String {
		return fmt.Errorf("schema: %s.%s: enum values need type %q", model, name, String)
	}
	// Step 3: "id" is reserved for the primary key
	if (f.Type == ID) != (name == "id") {
		return fmt.Errorf("schema: %s.%s: type %q is only valid for the id field", model, name, ID)
	}
	// Step 4: a reference needs a target
	if f.References != nil && (f.References.Model == "" || f.References.Field == "") {
		return fmt.Errorf("schema: %s.%s: references need a model and a field", model, name)
	}
	return nil
}
