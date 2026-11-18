package schema

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"time"
)

// TypeError reports a value that doesn't fit a field's logical type.
type TypeError struct {
	// Expected is the logical type (or "enum").
	Expected FieldType
	// Received describes the Go value in JavaScript terms ("string", "number", "boolean", "array", ...).
	Received string
	// Options are the allowed values when an enum check failed.
	Options []string
}

func (e *TypeError) Error() string {
	if len(e.Options) > 0 {
		quoted := make([]string, len(e.Options))
		for i, o := range e.Options {
			quoted[i] = fmt.Sprintf("%q", o)
		}
		return "Invalid option: expected one of " + strings.Join(quoted, "|")
	}
	return fmt.Sprintf("Invalid input: expected %s, received %s", expectedName(e.Expected), e.Received)
}

// expectedName spells a logical type the way zod's messages do.
func expectedName(t FieldType) string {
	switch t {
	case Integer:
		return "int"
	case Date:
		return "date"
	case StringArray, NumberArray:
		return "array"
	case ID:
		return "string"
	}
	return string(t)
}

// DateMillis truncates t to millisecond precision in UTC: better-auth's Date resolution, and what every
// backend can store (MySQL datetime(3)).
func DateMillis(t time.Time) time.Time { return t.UTC().Truncate(time.Millisecond) }

// dateLayouts are the string forms accepted for date fields (JavaScript's Date parses all of them).
var dateLayouts = []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05.999999999Z07:00", "2006-01-02 15:04:05.999999999", "2006-01-02"}

// ParseDate parses an ISO 8601 / RFC 3339 date string (date-only strings are midnight UTC).
func ParseDate(s string) (time.Time, bool) {
	for _, layout := range dateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return DateMillis(t), true
		}
	}
	return time.Time{}, false
}

// Normalize converts a Go value to the canonical Go representation of logical type t:
// string (string, id), float64 (number), int64 (integer), bool (boolean), time.Time in UTC with millisecond
// precision (date; RFC 3339 strings are parsed), json.RawMessage (json), []string (string[]) and
// []float64 (number[]). nil and nil pointers stay nil. Values of another type give a *TypeError.
func Normalize(t FieldType, v any) (any, error) {
	// Step 1: unwrap pointers (nil pointer = nil)
	rv := reflect.ValueOf(v)
	for rv.IsValid() && rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return nil, nil
		}
		rv = rv.Elem()
	}
	if !rv.IsValid() {
		return nil, nil
	}
	v = rv.Interface()

	// Step 2: convert per logical type
	switch t {
	case String, ID:
		if rv.Kind() == reflect.String {
			return rv.String(), nil
		}
	case Number:
		if f, ok := toFloat(v, rv); ok {
			return f, nil
		}
	case Integer:
		if f, ok := toFloat(v, rv); ok && f == math.Trunc(f) && !math.IsInf(f, 0) {
			if n, isInt := v.(json.Number); isInt {
				if i, err := n.Int64(); err == nil {
					return i, nil
				}
			}
			if rv.CanInt() {
				return rv.Int(), nil
			}
			return int64(f), nil
		}
	case Boolean:
		if rv.Kind() == reflect.Bool {
			return rv.Bool(), nil
		}
	case Date:
		switch x := v.(type) {
		case time.Time:
			return DateMillis(x), nil
		case string:
			if d, ok := ParseDate(x); ok {
				return d, nil
			}
			return nil, &TypeError{Expected: Date, Received: "Invalid Date"}
		}
	case JSON:
		switch x := v.(type) {
		case json.RawMessage:
			if !json.Valid(x) {
				return nil, &TypeError{Expected: JSON, Received: "invalid JSON"}
			}
			return append(json.RawMessage(nil), x...), nil
		default:
			b, err := json.Marshal(x)
			if err != nil {
				return nil, &TypeError{Expected: JSON, Received: jsKind(rv)}
			}
			return json.RawMessage(b), nil
		}
	case StringArray:
		if rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array {
			out := make([]string, rv.Len())
			for i := range out {
				e := reflect.Indirect(reflect.ValueOf(rv.Index(i).Interface()))
				if !e.IsValid() || e.Kind() != reflect.String {
					return nil, &TypeError{Expected: String, Received: jsKind(e)}
				}
				out[i] = e.String()
			}
			return out, nil
		}
	case NumberArray:
		if rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array {
			out := make([]float64, rv.Len())
			for i := range out {
				e := reflect.Indirect(reflect.ValueOf(rv.Index(i).Interface()))
				f, ok := toFloat(nil, e)
				if !e.IsValid() || !ok {
					return nil, &TypeError{Expected: Number, Received: jsKind(e)}
				}
				out[i] = f
			}
			return out, nil
		}
	default:
		return nil, fmt.Errorf("schema: unknown field type %q", t)
	}
	return nil, &TypeError{Expected: t, Received: jsKind(rv)}
}

// toFloat converts numeric kinds and json.Number to float64.
func toFloat(v any, rv reflect.Value) (float64, bool) {
	if n, ok := v.(json.Number); ok {
		f, err := n.Float64()
		return f, err == nil
	}
	if !rv.IsValid() {
		return 0, false
	}
	switch {
	case rv.CanInt():
		return float64(rv.Int()), true
	case rv.CanUint():
		return float64(rv.Uint()), true
	case rv.CanFloat():
		return rv.Float(), true
	case rv.Kind() == reflect.Interface && !rv.IsNil():
		return toFloat(rv.Elem().Interface(), rv.Elem())
	}
	return 0, false
}

// jsKind names a Go value's kind the way JavaScript / zod would ("string", "number", "array", ...).
func jsKind(rv reflect.Value) string {
	if !rv.IsValid() {
		return "null"
	}
	if _, ok := rv.Interface().(json.Number); ok {
		return "number"
	}
	if _, ok := rv.Interface().(time.Time); ok {
		return "Date"
	}
	switch rv.Kind() {
	case reflect.String:
		return "string"
	case reflect.Bool:
		return "boolean"
	case reflect.Slice, reflect.Array:
		return "array"
	case reflect.Map, reflect.Struct:
		return "object"
	case reflect.Interface, reflect.Pointer:
		if rv.IsNil() {
			return "null"
		}
		return jsKind(rv.Elem())
	}
	if rv.CanInt() || rv.CanUint() || rv.CanFloat() {
		return "number"
	}
	return rv.Kind().String()
}

// checkEnum validates v (already normalised) against the field's enum values.
func checkEnum(f Field, v any) error {
	s, ok := v.(string)
	if len(f.Enum) == 0 || !ok {
		return nil
	}
	for _, e := range f.Enum {
		if s == e {
			return nil
		}
	}
	return &TypeError{Expected: String, Received: "string", Options: f.Enum}
}

// truthy is JavaScript truthiness for decoded JSON values (false, 0, NaN, "", null are falsy).
func truthy(v any) bool {
	rv := reflect.ValueOf(v)
	for rv.IsValid() && rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return false
		}
		rv = rv.Elem()
	}
	if !rv.IsValid() {
		return false
	}
	if n, ok := rv.Interface().(json.Number); ok {
		f, err := n.Float64()
		return err == nil && f != 0
	}
	switch {
	case rv.Kind() == reflect.Bool:
		return rv.Bool()
	case rv.Kind() == reflect.String:
		return rv.String() != ""
	case rv.CanInt():
		return rv.Int() != 0
	case rv.CanUint():
		return rv.Uint() != 0
	case rv.CanFloat():
		f := rv.Float()
		return f != 0 && !math.IsNaN(f)
	}
	return true
}
