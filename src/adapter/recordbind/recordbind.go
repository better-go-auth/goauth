// Package recordbind maps Go structs to adapter records and back for plugin repositories: each Go field is
// bound to a registry field by name, so a plugin keeps its typed models while it stores them through
// adapter.Adapter (any backend, either column case, application or database ids).
//
//	b, err := recordbind.New[models.Passkey](reg, "passkey",
//		recordbind.Field{Go: "ID", Name: "id"},
//		recordbind.Field{Go: "UserID", Name: "userId"},
//	)
//	rec, err := store.Create(ctx, b.Model(), b.Record(pk))
//	pk, err = b.Decode(rec)
//
// Go fields whose registry field is missing (an optional plugin field that is turned off, e.g. the
// invitation's teamId without teams) are never written and decode as their zero value.
package recordbind

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/schema"
)

// Field binds one Go struct field to a registry field.
type Field struct {
	// Go is the Go field name (promoted fields of embedded structs work, e.g. "ID" of models.Base).
	Go string
	// Name is the logical registry field name ("userId").
	Name string
	// JSON stores the Go value as a JSON string (better-auth keeps documents such as the organization role's
	// permission in "string" fields).
	JSON bool
}

// bound is a Field resolved against the struct type and the registry model.
type bound struct {
	Field
	index []int
	// hasDefault reports whether the registry field has a default
	hasDefault bool
}

// Binding maps T to the records of one registry model.
type Binding[T any] struct {
	model  *schema.ResolvedModel
	fields []bound
	keys   map[string]int
}

// New binds the Go fields of T to model of reg. A Go field that does not exist is an error (a programming
// mistake); a registry field that does not exist leaves the Go field unbound.
func New[T any](reg *schema.Registry, model string, fields ...Field) (*Binding[T], error) {
	// Step 1: the registry model
	m, ok := reg.Model(model)
	if !ok {
		return nil, fmt.Errorf("recordbind: the schema registry has no %q model", model)
	}
	typ := reflect.TypeOf((*T)(nil)).Elem()
	if typ.Kind() != reflect.Struct {
		return nil, fmt.Errorf("recordbind: %s is not a struct", typ)
	}
	b := &Binding[T]{model: m, keys: map[string]int{}}
	// Step 2: every Go field, bound or not
	for _, f := range fields {
		sf, ok := typ.FieldByName(f.Go)
		if !ok {
			return nil, fmt.Errorf("recordbind: %s has no field %s", typ.Name(), f.Go)
		}
		if !m.Has(f.Name) {
			continue
		}
		i := len(b.fields)
		rf, _ := m.Field(f.Name)
		b.fields = append(b.fields, bound{Field: f, index: sf.Index, hasDefault: rf.HasDefault()})
		// Step 3: update keys: Go name, registry name and column (what GORM's Updates accepted)
		b.keys[f.Go] = i
		b.keys[f.Name] = i
		b.keys[m.Column(f.Name)] = i
	}
	return b, nil
}

// MustNew is New for bindings that are fixed at compile time; it panics on error.
func MustNew[T any](reg *schema.Registry, model string, fields ...Field) *Binding[T] {
	b, err := New[T](reg, model, fields...)
	if err != nil {
		panic(err)
	}
	return b
}

// Model returns the logical model name.
func (b *Binding[T]) Model() string { return b.model.Name() }

// Has reports whether the registry model has field (logical name).
func (b *Binding[T]) Has(field string) bool { return b.model.Has(field) }

// Record converts v to a record for Create. A zero id and zero dates are left out, so the adapter generates
// the id (or the database does) and date defaults apply, and so are other zero values of fields with a
// registry default (an empty status gets "active", like GORM's `default:` tags did); booleans are always
// written (false is a value). nil pointers are written as null.
func (b *Binding[T]) Record(v *T) adapter.Record {
	rv := reflect.ValueOf(v).Elem()
	rec := adapter.Record{}
	for _, f := range b.fields {
		fv := rv.FieldByIndex(f.index)
		// Step 1: values the adapter or the defaults fill in
		if fv.IsZero() && (f.Name == "id" || fv.Type() == reflect.TypeOf(time.Time{}) || (f.hasDefault && fv.Kind() != reflect.Bool)) {
			continue
		}
		// Step 2: the stored value
		x, err := toRecord(f, fv)
		if err != nil {
			// a value json.Marshal rejects can't come from the plugin models (maps of strings)
			continue
		}
		rec[f.Name] = x
	}
	return rec
}

// toRecord returns the value stored for one Go field.
func toRecord(f bound, fv reflect.Value) (any, error) {
	if fv.Kind() == reflect.Pointer && fv.IsNil() {
		return nil, nil
	}
	if f.JSON {
		if (fv.Kind() == reflect.Map || fv.Kind() == reflect.Slice) && fv.IsNil() {
			return nil, nil
		}
		raw, err := json.Marshal(fv.Interface())
		if err != nil {
			return nil, err
		}
		return string(raw), nil
	}
	return fv.Interface(), nil
}

// Decode converts a record returned by the adapter into a new T.
func (b *Binding[T]) Decode(rec adapter.Record) (*T, error) {
	out := new(T)
	rv := reflect.ValueOf(out).Elem()
	for _, f := range b.fields {
		if err := setField(f, rv.FieldByIndex(f.index), rec[f.Name]); err != nil {
			return nil, fmt.Errorf("recordbind: %s.%s: %w", b.model.Name(), f.Name, err)
		}
	}
	return out, nil
}

// DecodeAll decodes every record (an empty, non-nil slice for none).
func (b *Binding[T]) DecodeAll(recs []adapter.Record) ([]T, error) {
	out := make([]T, 0, len(recs))
	for _, rec := range recs {
		v, err := b.Decode(rec)
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	return out, nil
}

// Updates converts an update map to a record. Keys may be Go field names (what goauth's services pass),
// registry field names or column names; values may be Go values of the bound fields or pointers to them.
func (b *Binding[T]) Updates(data map[string]any) (adapter.Record, error) {
	rec := adapter.Record{}
	for k, x := range data {
		i, ok := b.keys[k]
		if !ok {
			return nil, fmt.Errorf("recordbind: unknown field %q on %s", k, b.model.Name())
		}
		f := b.fields[i]
		v, err := updateValue(f, x)
		if err != nil {
			return nil, fmt.Errorf("recordbind: %s.%s: %w", b.model.Name(), f.Name, err)
		}
		rec[f.Name] = v
	}
	return rec, nil
}

// updateValue returns the stored value of an update entry.
func updateValue(f bound, x any) (any, error) {
	if x == nil {
		return nil, nil
	}
	rv := reflect.ValueOf(x)
	if rv.Kind() == reflect.Pointer && rv.IsNil() {
		return nil, nil
	}
	if f.JSON {
		if s, ok := x.(string); ok {
			return s, nil
		}
		return toRecord(f, rv)
	}
	return x, nil
}

// setField assigns a record value (canonical adapter type) to a struct field.
func setField(f bound, dst reflect.Value, x any) error {
	// Step 1: null
	if x == nil {
		dst.Set(reflect.Zero(dst.Type()))
		return nil
	}
	// Step 2: JSON documents stored as strings
	if f.JSON {
		raw, ok := x.(string)
		if !ok {
			b, err := json.Marshal(x)
			if err != nil {
				return err
			}
			raw = string(b)
		}
		target := reflect.New(dst.Type())
		if strings.TrimSpace(raw) != "" {
			if err := json.Unmarshal([]byte(raw), target.Interface()); err != nil {
				return err
			}
		}
		dst.Set(target.Elem())
		return nil
	}
	// Step 3: scalars, through a pointer when the field is one
	target := dst
	if dst.Kind() == reflect.Pointer {
		target = reflect.New(dst.Type().Elem()).Elem()
	}
	xv := reflect.ValueOf(x)
	switch {
	case xv.Type().AssignableTo(target.Type()):
		target.Set(xv)
	case xv.Kind() == reflect.String && target.Kind() == reflect.String,
		xv.Kind() == reflect.Bool && target.Kind() == reflect.Bool,
		(xv.CanInt() || xv.CanFloat()) && (target.CanInt() || target.CanFloat()):
		target.Set(xv.Convert(target.Type()))
	case xv.Kind() == reflect.String && (target.CanInt() || target.CanFloat()):
		// id strategy serial: ids come back as numbers or numeric strings depending on the backend
		n := json.Number(xv.String())
		fl, err := n.Float64()
		if err != nil {
			return fmt.Errorf("cannot assign %T to %s", x, dst.Type())
		}
		target.Set(reflect.ValueOf(fl).Convert(target.Type()))
	case (xv.CanInt() || xv.CanFloat()) && target.Kind() == reflect.String:
		target.SetString(fmt.Sprint(x))
	default:
		return fmt.Errorf("cannot assign %T to %s", x, dst.Type())
	}
	if dst.Kind() == reflect.Pointer {
		dst.Set(target.Addr())
	}
	return nil
}
