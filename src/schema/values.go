package schema

import (
	"encoding/json"
	"fmt"
	"reflect"
	"time"
)

// ExtraGetter is implemented by records that hold runtime (additionalFields / plugin) values, such as
// models.User, models.Session, models.Account and models.Verification, and by Values.
type ExtraGetter interface {
	GetExtra(key string) (any, bool)
}

// ExtraSetter is implemented by records whose runtime values can be changed.
type ExtraSetter interface {
	SetExtra(key string, value any)
}

// Values adapts a plain map (e.g. an adapter record or a parsed request body) to ExtraGetter/ExtraSetter.
type Values map[string]any

// GetExtra returns the value stored under key.
func (v Values) GetExtra(key string) (any, bool) {
	x, ok := v[key]
	return x, ok
}

// SetExtra stores value under key.
func (v Values) SetExtra(key string, value any) { v[key] = value }

// Get returns the runtime value key of h converted to T, e.g. schema.Get[string](user, "loyaltyTier").
// Numbers convert between numeric types, json.RawMessage values decode into T, and a missing, nil or
// unconvertible value returns ok=false.
func Get[T any](h ExtraGetter, key string) (T, bool) {
	var zero T
	if h == nil {
		return zero, false
	}
	v, ok := h.GetExtra(key)
	if !ok || v == nil {
		return zero, false
	}
	var out T
	if err := assign(reflect.ValueOf(&out).Elem(), v); err != nil {
		return zero, false
	}
	return out, true
}

// Set stores a runtime value on h, e.g. schema.Set(user, "loyaltyTier", "gold"). The value is validated
// against the registry when the record is saved.
func Set(h ExtraSetter, key string, value any) { h.SetExtra(key, value) }

// Bind copies runtime values of h into the struct pointed to by dst. Struct fields name their key with a
// `field:"loyaltyTier"` tag; untagged fields and missing values are left unchanged.
//
//	type Profile struct{ LoyaltyTier string `field:"loyaltyTier"` }
//	var p Profile
//	err := schema.Bind(user, &p)
func Bind(h ExtraGetter, dst any) error {
	rv := reflect.ValueOf(dst)
	if rv.Kind() != reflect.Pointer || rv.IsNil() || rv.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("schema: Bind needs a non-nil struct pointer, got %T", dst)
	}
	st := rv.Elem()
	for i := 0; i < st.NumField(); i++ {
		sf := st.Type().Field(i)
		key := sf.Tag.Get("field")
		if key == "" || key == "-" || !sf.IsExported() {
			continue
		}
		v, ok := h.GetExtra(key)
		if !ok || v == nil {
			continue
		}
		if err := assign(st.Field(i), v); err != nil {
			return fmt.Errorf("schema: Bind %s (%q): %w", sf.Name, key, err)
		}
	}
	return nil
}

// assign sets dst from v, converting between compatible representations.
func assign(dst reflect.Value, v any) error {
	src := reflect.ValueOf(v)
	// Step 1: direct assignment
	if src.Type().AssignableTo(dst.Type()) {
		dst.Set(src)
		return nil
	}
	// Step 2: pointer destinations get a new value
	if dst.Kind() == reflect.Pointer {
		p := reflect.New(dst.Type().Elem())
		if err := assign(p.Elem(), v); err != nil {
			return err
		}
		dst.Set(p)
		return nil
	}
	// Step 3: pointer sources are dereferenced
	if src.Kind() == reflect.Pointer {
		if src.IsNil() {
			return fmt.Errorf("nil value")
		}
		return assign(dst, src.Elem().Interface())
	}
	// Step 4: json.RawMessage decodes into anything
	if raw, ok := v.(json.RawMessage); ok {
		return json.Unmarshal(raw, dst.Addr().Interface())
	}
	// Step 5: numeric and string kinds convert (time.Time is a struct and never reaches here)
	numeric := func(k reflect.Kind) bool {
		return (k >= reflect.Int && k <= reflect.Float64) && k != reflect.Uintptr
	}
	if (numeric(src.Kind()) && numeric(dst.Kind())) || (src.Kind() == reflect.String && dst.Kind() == reflect.String) ||
		(src.Kind() == reflect.Bool && dst.Kind() == reflect.Bool) {
		dst.Set(src.Convert(dst.Type()))
		return nil
	}
	// Step 6: RFC 3339 strings into time.Time
	if s, ok := v.(string); ok && dst.Type() == reflect.TypeOf(time.Time{}) {
		if t, ok := ParseDate(s); ok {
			dst.Set(reflect.ValueOf(t))
			return nil
		}
	}
	// Step 7: slices convert element by element
	if (src.Kind() == reflect.Slice || src.Kind() == reflect.Array) && dst.Kind() == reflect.Slice {
		out := reflect.MakeSlice(dst.Type(), src.Len(), src.Len())
		for i := 0; i < src.Len(); i++ {
			e := src.Index(i).Interface()
			if e == nil {
				continue
			}
			if err := assign(out.Index(i), e); err != nil {
				return err
			}
		}
		dst.Set(out)
		return nil
	}
	return fmt.Errorf("cannot use %T as %s", v, dst.Type())
}
