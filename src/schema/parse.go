package schema

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/better-go-auth/goauth/src/common/autherr"
)

// Action is the operation input is parsed for.
type Action string

const (
	// ActionCreate applies defaults and checks required fields.
	ActionCreate Action = "create"
	// ActionUpdate skips defaults and required checks (partial updates).
	ActionUpdate Action = "update"
)

// ParseInput is better-auth's parseUserInput / parseSessionInput / parseAccountInput for model: it parses
// a request body against the model's input fields (goauth built-ins, additionalFields and plugin fields;
// better-auth core fields such as name and email are left to the endpoints) and returns the accepted
// values keyed by field name. See ParseInputData for the rules.
func (r *Registry) ParseInput(model string, data map[string]any, action Action) (map[string]any, error) {
	m, ok := r.models[model]
	if !ok {
		return nil, fmt.Errorf("schema: unknown model %q", model)
	}
	return parseInput(m.InputFields(), data, action)
}

// ParseInputData is a port of better-auth's parseInputData (better-auth/dist/db/schema.mjs). For every
// field, in name order:
//
//   - key present, field input:false: on create a field with a Default gets the default; otherwise a truthy
//     value fails with 400 FIELD_NOT_ALLOWED "<key> is not allowed to be set" and a falsy one is dropped.
//   - key present: the value is converted to the field's logical type (400 VALIDATION_ERROR when it doesn't
//     fit: goauth's equivalent of better-auth's zod body schema), then Validate runs (its error message
//     becomes the VALIDATION_ERROR message), or else TransformIn.
//   - key missing on create: the Default when there is one, else 400 MISSING_FIELD "<key> is required" for
//     Required fields. On update neither applies.
//   - keys that are not fields are dropped silently.
func ParseInputData(fields map[string]Field, data map[string]any, action Action) (map[string]any, error) {
	list := make([]ResolvedField, 0, len(fields))
	for _, name := range sortedKeys(fields) {
		list = append(list, ResolvedField{Field: fields[name], Name: name})
	}
	return parseInput(list, data, action)
}

// parseInput implements ParseInputData over resolved fields, in their order.
func parseInput(fields []ResolvedField, data map[string]any, action Action) (map[string]any, error) {
	if action == "" {
		action = ActionCreate
	}
	out := map[string]any{}
	for _, f := range fields {
		key := f.Name
		v, present := data[key]
		if present {
			// Step 1: input:false fields: default on create, rejected when set to a truthy value
			if !f.IsInput() {
				if f.HasDefault() && action != ActionUpdate {
					d, err := normalizeDefault(f)
					if err != nil {
						return nil, err
					}
					out[key] = d
					continue
				}
				if truthy(v) {
					return nil, autherr.ErrFieldNotAllowed.WithMessage(key + " is not allowed to be set")
				}
				continue
			}
			// Step 2: the value must fit the logical type (and the enum)
			cv, err := Normalize(f.Type, v)
			if err == nil {
				err = checkEnum(f.Field, cv)
			}
			if err != nil {
				var te *TypeError
				if errors.As(err, &te) {
					return nil, autherr.ErrValidationError.WithMessage("[body." + key + "] " + te.Error())
				}
				return nil, err
			}
			// Step 3: validator (better-auth's validator.input), which may convert the value
			if f.Validate != nil {
				res, err := f.Validate(cv)
				if err != nil {
					msg := err.Error()
					if msg == "" {
						msg = autherr.ErrValidationError.Message
					}
					return nil, autherr.ErrValidationError.WithMessage(msg)
				}
				out[key] = res
				continue
			}
			// Step 4: transform (better-auth's transform.input)
			if f.TransformIn != nil {
				out[key] = f.TransformIn(cv)
				continue
			}
			out[key] = cv
			continue
		}
		// Step 5: missing on create: default, else required error
		if action != ActionCreate {
			continue
		}
		if f.HasDefault() {
			d, err := normalizeDefault(f)
			if err != nil {
				return nil, err
			}
			out[key] = d
			continue
		}
		if f.Required {
			return nil, autherr.ErrMissingField.WithMessage(key + " is required")
		}
	}
	return out, nil
}

// normalizeDefault evaluates a field's default and converts it to the canonical Go type.
func normalizeDefault(f ResolvedField) (any, error) {
	d, err := Normalize(f.Type, f.DefaultValue())
	if err != nil {
		return nil, fmt.Errorf("schema: default of %q: %w", f.Name, err)
	}
	return d, nil
}

// ParseOutput is better-auth's parseUserOutput / parseSessionOutput (filterOutputFields): a copy of data
// without the model's returned:false fields. Other keys, including unknown ones, are kept as they are.
func (r *Registry) ParseOutput(model string, data map[string]any) map[string]any {
	if data == nil {
		return nil
	}
	m, ok := r.models[model]
	out := make(map[string]any, len(data))
	for k, v := range data {
		if ok {
			if f, known := m.Field(k); known && !f.IsReturned() {
				continue
			}
		}
		out[k] = v
	}
	return out
}

// BuildOutput is better-auth's buildSyntheticUserOutput generalised to any model: every returned field of
// the model, with the value from data when present and not nil, else the field's default, else nil for
// optional fields (required fields without a value are left out). Keys of data that are not fields are
// dropped. This is the shape API responses use, so absent optional fields appear as null.
func (r *Registry) BuildOutput(model string, data map[string]any) map[string]any {
	m, ok := r.models[model]
	if !ok {
		return nil
	}
	out := map[string]any{}
	for _, f := range m.OutputFields() {
		// OmitEmpty fields (goauth's own columns) only appear when they hold a non-default value
		if f.OmitEmpty {
			if v := data[f.Name]; !f.EmptyOutput(v) {
				out[f.Name] = v
			}
			continue
		}
		if v, present := data[f.Name]; present && v != nil {
			out[f.Name] = v
			continue
		}
		if f.HasDefault() {
			if d, err := Normalize(f.Type, f.DefaultValue()); err == nil {
				out[f.Name] = d
				continue
			}
		}
		if !f.Required {
			out[f.Name] = nil
		}
	}
	return out
}

// EmptyOutput reports whether v counts as "not set" for an OmitEmpty field: nil, a nil pointer, the zero
// value of its type, or the field's Default.
func (f Field) EmptyOutput(v any) bool {
	// Step 1: nil and zero values (nil pointers, "", false, 0, zero times, empty slices)
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return true
		}
		rv = rv.Elem()
	}
	if rv.IsZero() || ((rv.Kind() == reflect.Slice || rv.Kind() == reflect.Map) && rv.Len() == 0) {
		return true
	}
	// Step 2: the default value (e.g. locale "en")
	if f.HasDefault() {
		d, err := Normalize(f.Type, f.DefaultValue())
		n, err2 := Normalize(f.Type, rv.Interface())
		if err == nil && err2 == nil && reflect.DeepEqual(d, n) {
			return true
		}
	}
	return false
}
