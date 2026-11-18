package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/providers/idgen"
	"github.com/better-go-auth/goauth/src/schema"
)

// Option configures New.
type Option func(*factory)

// WithIDGenerator replaces idgen.GenerateID (the process-wide generator) for new records.
func WithIDGenerator(fn func() string) Option {
	return func(f *factory) { f.genID = fn }
}

// factory implements Adapter on top of a Backend (better-auth's createAdapterFactory).
type factory struct {
	reg   *schema.Registry
	b     Backend
	caps  Capabilities
	genID func() string
	// ids is the registry's id strategy: with IDDatabase / IDSerial the database creates ids, and with
	// IDSerial every field holding an id is stored as an integer (strings in records).
	ids schema.IDStrategy
}

// New wraps backend b in the shared factory for registry reg. With the registry's id strategy IDDatabase
// or IDSerial, records created without an id get the id the database generates (WithIDGenerator is then
// not used).
func New(reg *schema.Registry, b Backend, opts ...Option) Adapter {
	f := &factory{reg: reg, b: b, caps: b.Capabilities(), genID: idgen.GenerateID, ids: reg.IDStrategy()}
	for _, o := range opts {
		o(f)
	}
	return f
}

// ID returns the backend ID.
func (f *factory) ID() string { return f.b.ID() }

// Unwrap returns the backend (see As).
func (f *factory) Unwrap() Backend { return f.b }

// Registry returns the registry the adapter maps names with.
func (f *factory) Registry() *schema.Registry { return f.reg }

// RegistryOf returns the registry of an adapter built by New (nil for other implementations).
func RegistryOf(a Adapter) *schema.Registry {
	if r, ok := a.(interface{ Registry() *schema.Registry }); ok {
		return r.Registry()
	}
	return nil
}

func (f *factory) model(name string) (*schema.ResolvedModel, error) {
	m, ok := f.reg.Model(name)
	if !ok {
		return nil, fmt.Errorf("%w %q", ErrUnknownModel, name)
	}
	return m, nil
}

// checkKeys rejects record keys that are not fields of m.
func checkKeys(m *schema.ResolvedModel, data Record) error {
	for k := range data {
		if !m.Has(k) {
			return fmt.Errorf("%w %q on model %q", ErrUnknownField, k, m.Name())
		}
	}
	return nil
}

// Create inserts data and returns the stored record (read back, so backend defaults are included).
func (f *factory) Create(ctx context.Context, model string, data Record) (Record, error) {
	m, err := f.model(model)
	if err != nil {
		return nil, err
	}
	// Step 1: unknown keys are programming errors
	if err := checkKeys(m, data); err != nil {
		return nil, err
	}
	// Step 2: build the row: id, defaults, transforms, normalisation and storage encoding
	row := Row{}
	var id string
	for _, fld := range m.Fields() {
		v, present := data[fld.Name]
		if fld.Name == "id" {
			// the id: given, generated here, or (id strategy database / serial) left to the database
			if s, _ := normalizeID(v); s != "" {
				id = s
			} else if !f.ids.DatabaseGenerated() {
				id = f.genID()
			}
			if id != "" {
				sv, err := f.idStorage(m, fld, id)
				if err != nil {
					return nil, err
				}
				row[fld.Column] = sv
			}
			continue
		}
		if (!present || (v == nil && fld.Required)) && fld.HasDefault() {
			v, present = fld.DefaultValue(), true
		}
		if !present && fld.TransformIn == nil {
			if fld.Required {
				return nil, &ValueError{Model: model, Field: fld.Name, Err: errors.New("value is required")}
			}
			continue
		}
		sv, err := f.toStorage(m, fld, v, true)
		if err != nil {
			return nil, err
		}
		row[fld.Column] = sv
	}
	// Step 3: insert and read the row back
	if id == "" {
		return f.createGeneratedID(ctx, m, row)
	}
	if err := f.b.Insert(ctx, m.Table(), row); err != nil {
		return nil, f.wrapUnique(m, err)
	}
	return f.FindOne(ctx, model, []Where{{Field: "id", Value: id}})
}

// createGeneratedID inserts a row without an id (id strategy database / serial) and reads it back by the id
// the database generated, or, when the backend can't report it, by the row's unique values.
func (f *factory) createGeneratedID(ctx context.Context, m *schema.ResolvedModel, row Row) (Record, error) {
	idCol := m.Column("id")
	// Step 1: insert, asking the backend for the new id
	var newID any
	if ib, ok := f.b.(IDInserter); ok {
		got, err := ib.InsertReturningID(ctx, m.Table(), row, idCol, f.ids == schema.IDSerial)
		if err != nil {
			return nil, f.wrapUnique(m, err)
		}
		newID = got
	} else if err := f.b.Insert(ctx, m.Table(), row); err != nil {
		return nil, f.wrapUnique(m, err)
	}
	// Step 2: read the row back by its id
	if newID != nil {
		rows, err := f.b.Select(ctx, m.Table(), Select{Where: []Cond{{Column: idCol, Op: Eq, Value: newID, Connector: And, Type: schema.ID}}, Limit: 1})
		if err != nil {
			return nil, err
		}
		if len(rows) == 1 {
			return f.toRecord(m, rows[0], nil)
		}
	}
	// Step 3: no id reported: a unique value identifies the row, else every value must match exactly one row
	var where []Cond
	for _, fld := range m.Fields() {
		if v, ok := row[fld.Column]; ok && v != nil && fld.Unique {
			where = []Cond{{Column: fld.Column, Op: Eq, Value: v, Connector: And, Type: fld.Type}}
			break
		}
	}
	if where == nil {
		for _, fld := range m.Fields() {
			if v, ok := row[fld.Column]; ok {
				where = append(where, Cond{Column: fld.Column, Op: Eq, Value: v, Connector: And, Type: fld.Type})
			}
		}
	}
	rows, err := f.b.Select(ctx, m.Table(), Select{Where: where, Limit: 2})
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, fmt.Errorf("adapter: %s: cannot identify the inserted row (the database generated its id); "+
			"give the model a unique field or let the backend report generated ids", m.Name())
	}
	return f.toRecord(m, rows[0], nil)
}

// normalizeID returns a record id as a string ("" for nil / empty).
func normalizeID(v any) (string, error) {
	if v == nil {
		return "", nil
	}
	nv, err := schema.Normalize(schema.ID, v)
	if err != nil {
		if rv := reflect.ValueOf(v); rv.CanInt() {
			return strconv.FormatInt(rv.Int(), 10), nil
		}
		return "", err
	}
	s, _ := nv.(string)
	return s, nil
}

// idStorage converts an id (or a reference to one) to its storage value: an int64 under IDSerial.
func (f *factory) idStorage(m *schema.ResolvedModel, fld schema.ResolvedField, id string) (any, error) {
	if f.ids != schema.IDSerial {
		return id, nil
	}
	n, err := strconv.ParseInt(strings.TrimSpace(id), 10, 64)
	if err != nil {
		return nil, &ValueError{Model: m.Name(), Field: fld.Name, Err: fmt.Errorf("serial id %q is not an integer", id)}
	}
	return n, nil
}

// toStorage turns a record value into the value the backend stores (create: required check included).
func (f *factory) toStorage(m *schema.ResolvedModel, fld schema.ResolvedField, v any, create bool) (any, error) {
	// Step 1: transform.input runs on the raw value (better-auth), then the value is normalised
	if fld.TransformIn != nil {
		v = fld.TransformIn(v)
	}
	nv, err := schema.Normalize(fld.Type, v)
	if err != nil {
		return nil, &ValueError{Model: m.Name(), Field: fld.Name, Err: err}
	}
	if nv == nil && fld.Required && create {
		return nil, &ValueError{Model: m.Name(), Field: fld.Name, Err: errors.New("value is required")}
	}
	// Step 2: references to serial ids are integers
	if f.ids == schema.IDSerial && fld.HoldsID() && nv != nil {
		s, err := normalizeID(nv)
		if err != nil {
			return nil, &ValueError{Model: m.Name(), Field: fld.Name, Err: err}
		}
		return f.idStorage(m, fld, s)
	}
	// Step 3: encode types the backend doesn't store natively
	return f.encode(fld.Type, nv)
}

// encode converts a normalised value to its storage representation.
func (f *factory) encode(t schema.FieldType, v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	switch t {
	case schema.JSON:
		if !f.caps.JSON {
			return string(v.(json.RawMessage)), nil
		}
	case schema.StringArray, schema.NumberArray:
		if !f.caps.Arrays {
			b, err := json.Marshal(v)
			if err != nil {
				return nil, err
			}
			return string(b), nil
		}
	case schema.Date:
		if !f.caps.Dates {
			return v.(time.Time).Format("2006-01-02T15:04:05.000Z07:00"), nil
		}
	case schema.Boolean:
		if !f.caps.Booleans {
			if v.(bool) {
				return 1, nil
			}
			return 0, nil
		}
	}
	return v, nil
}

// decode converts a stored value back to the canonical Go type of t.
func decode(t schema.FieldType, v any) (any, error) {
	if b, ok := v.([]byte); ok {
		v = string(b)
	}
	if v == nil {
		return nil, nil
	}
	switch t {
	case schema.String, schema.ID:
		if x, ok := v.(string); ok {
			return x, nil
		}
		// numeric ids (serial columns)
		if rv := reflect.ValueOf(v); rv.CanInt() || rv.CanUint() {
			return fmt.Sprint(v), nil
		}
	case schema.Boolean:
		// tinyint / integer columns (MySQL, SQLite) scan as any integer type
		if rv := reflect.ValueOf(v); rv.CanInt() || rv.CanUint() || rv.CanFloat() {
			return !rv.IsZero(), nil
		}
		switch x := v.(type) {
		case bool:
			return x, nil
		case string:
			switch strings.ToLower(x) {
			case "1", "t", "true":
				return true, nil
			case "0", "f", "false":
				return false, nil
			}
		}
	case schema.Date:
		switch x := v.(type) {
		case time.Time:
			return schema.DateMillis(x), nil
		case string:
			if d, ok := schema.ParseDate(x); ok {
				return d, nil
			}
		case int64:
			return schema.DateMillis(time.UnixMilli(x)), nil
		}
	case schema.Number, schema.Integer:
		if s, ok := v.(string); ok {
			n, err := strconv.ParseFloat(s, 64)
			if err != nil {
				return nil, err
			}
			v = n
		}
		return schema.Normalize(t, v)
	case schema.JSON:
		if s, ok := v.(string); ok {
			if !json.Valid([]byte(s)) {
				return nil, fmt.Errorf("invalid JSON %q", s)
			}
			return json.RawMessage(s), nil
		}
		return schema.Normalize(t, v)
	case schema.StringArray, schema.NumberArray:
		if s, ok := v.(string); ok {
			var arr []any
			if err := json.Unmarshal([]byte(s), &arr); err != nil {
				return nil, err
			}
			v = arr
		}
		return schema.Normalize(t, v)
	}
	return nil, fmt.Errorf("cannot read %T as %s", v, t)
}

// toRecord converts a backend row to a record (unknown columns, e.g. legacy ones, are ignored).
func (f *factory) toRecord(m *schema.ResolvedModel, row Row, sel []string) (Record, error) {
	rec := Record{}
	for _, fld := range m.Fields() {
		if len(sel) > 0 && !contains(sel, fld.Name) {
			continue
		}
		// a column the row doesn't have (not stored yet, or not migrated yet) reads as NULL
		v, err := decode(fld.Type, row[fld.Column])
		if err != nil {
			return nil, &ValueError{Model: m.Name(), Field: fld.Name, Err: err}
		}
		if fld.TransformOut != nil {
			v = fld.TransformOut(v)
		}
		rec[fld.Name] = v
	}
	return rec, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// conds translates Where conditions to backend conditions.
func (f *factory) conds(m *schema.ResolvedModel, where []Where) ([]Cond, error) {
	out := make([]Cond, 0, len(where))
	for _, w := range where {
		fld, ok := m.Field(w.Field)
		if !ok {
			return nil, fmt.Errorf("%w %q on model %q", ErrUnknownField, w.Field, m.Name())
		}
		op := w.Op
		if op == "" {
			op = Eq
		}
		conn := w.Connector
		if conn == "" {
			conn = And
		}
		c := Cond{Column: fld.Column, Op: op, Connector: conn, Insensitive: w.Insensitive, Type: fld.Type}
		switch op {
		case In, NotIn:
			// Step 1: list operators take a slice of values
			list, err := toList(w.Value)
			if err != nil {
				return nil, &ValueError{Model: m.Name(), Field: fld.Name, Err: err}
			}
			vals := make([]any, len(list))
			for i, v := range list {
				if vals[i], err = f.whereValue(fld, v); err != nil {
					return nil, &ValueError{Model: m.Name(), Field: fld.Name, Err: err}
				}
			}
			c.Value = vals
		case Contains, StartsWith, EndsWith:
			// Step 2: pattern operators take a string
			s, ok := w.Value.(string)
			if !ok {
				return nil, &ValueError{Model: m.Name(), Field: fld.Name, Err: fmt.Errorf("%s needs a string, got %T", op, w.Value)}
			}
			c.Value = s
		case Eq, Ne, Lt, Lte, Gt, Gte:
			// Step 3: comparison operators take one value of the field's type
			v, err := f.whereValue(fld, w.Value)
			if err != nil {
				return nil, &ValueError{Model: m.Name(), Field: fld.Name, Err: err}
			}
			c.Value = v
		default:
			return nil, fmt.Errorf("adapter: unknown operator %q", op)
		}
		out = append(out, c)
	}
	return out, nil
}

// whereValue normalises and encodes one where value (better-auth also turns "true"/"false" and numeric
// strings into booleans and numbers).
func (f *factory) whereValue(fld schema.ResolvedField, v any) (any, error) {
	if s, ok := v.(string); ok {
		switch fld.Type {
		case schema.Boolean:
			v = s == "true"
		case schema.Number, schema.Integer:
			if n, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
				v = n
			}
		}
	}
	// serial ids: a value that is not an integer matches no row (-1 is never generated)
	if f.ids == schema.IDSerial && fld.HoldsID() && v != nil {
		s, err := normalizeID(v)
		if err != nil {
			return nil, err
		}
		n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil {
			return int64(-1), nil
		}
		return n, nil
	}
	nv, err := schema.Normalize(fld.Type, v)
	if err != nil {
		return nil, err
	}
	return f.encode(fld.Type, nv)
}

// toList turns a slice of any element type into []any.
func toList(v any) ([]any, error) {
	switch x := v.(type) {
	case []any:
		return x, nil
	case []string:
		out := make([]any, len(x))
		for i, s := range x {
			out[i] = s
		}
		return out, nil
	case nil:
		return nil, errors.New("in / not_in need a slice")
	}
	list, err := schema.Normalize(schema.StringArray, v)
	if err == nil {
		return toList(list)
	}
	nums, err := schema.Normalize(schema.NumberArray, v)
	if err != nil {
		return nil, errors.New("in / not_in need a slice")
	}
	out := make([]any, 0)
	for _, n := range nums.([]float64) {
		out = append(out, n)
	}
	return out, nil
}

// FindOne returns the first matching record.
func (f *factory) FindOne(ctx context.Context, model string, where []Where, sel ...string) (Record, error) {
	recs, err := f.find(ctx, model, Query{Where: where, Limit: 1, Select: sel})
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		return nil, ErrNotFound
	}
	return recs[0], nil
}

// FindMany returns the matching records.
func (f *factory) FindMany(ctx context.Context, model string, q Query) ([]Record, error) {
	return f.find(ctx, model, q)
}

func (f *factory) find(ctx context.Context, model string, q Query) ([]Record, error) {
	m, err := f.model(model)
	if err != nil {
		return nil, err
	}
	// Step 1: translate conditions, order and selected fields to physical names
	cs, err := f.conds(m, q.Where)
	if err != nil {
		return nil, err
	}
	sel := Select{Where: cs, Limit: q.Limit, Offset: q.Offset}
	for _, s := range q.Sort {
		fld, ok := m.Field(s.Field)
		if !ok {
			return nil, fmt.Errorf("%w %q on model %q", ErrUnknownField, s.Field, model)
		}
		sel.Order = append(sel.Order, Order{Column: fld.Column, Desc: s.Desc})
	}
	for _, name := range q.Select {
		fld, ok := m.Field(name)
		if !ok {
			return nil, fmt.Errorf("%w %q on model %q", ErrUnknownField, name, model)
		}
		sel.Columns = append(sel.Columns, fld.Column)
	}
	// every column is named (never SELECT *): columns the registry doesn't know are not read, and SQL
	// drivers that cache prepared statements (pgx) don't break when a migration adds a column
	if len(sel.Columns) == 0 {
		for _, fld := range m.Fields() {
			sel.Columns = append(sel.Columns, fld.Column)
		}
	}
	// Step 2: query and convert rows to records
	rows, err := f.b.Select(ctx, m.Table(), sel)
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(rows))
	for _, row := range rows {
		rec, err := f.toRecord(m, row, q.Select)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}

// Count counts the matching records.
func (f *factory) Count(ctx context.Context, model string, where []Where) (int64, error) {
	m, err := f.model(model)
	if err != nil {
		return 0, err
	}
	cs, err := f.conds(m, where)
	if err != nil {
		return 0, err
	}
	return f.b.Count(ctx, m.Table(), cs)
}

// updateSet builds the SET of an update: the given fields plus every OnUpdate field not set explicitly.
func (f *factory) updateSet(m *schema.ResolvedModel, data Record) (Row, error) {
	if err := checkKeys(m, data); err != nil {
		return nil, err
	}
	set := Row{}
	for _, fld := range m.Fields() {
		v, present := data[fld.Name]
		if !present {
			if fld.OnUpdate == nil {
				continue
			}
			v = fld.OnUpdate()
		}
		sv, err := f.toStorage(m, fld, v, false)
		if err != nil {
			return nil, err
		}
		set[fld.Column] = sv
	}
	return set, nil
}

// Update changes the first matching record and returns it.
func (f *factory) Update(ctx context.Context, model string, where []Where, data Record) (Record, error) {
	m, err := f.model(model)
	if err != nil {
		return nil, err
	}
	// Step 1: the first matching row
	first, err := f.FindOne(ctx, model, where, "id")
	if err != nil {
		return nil, err
	}
	// Step 2: update it (the original conditions stay, so a concurrent change makes it a no-op)
	set, err := f.updateSet(m, data)
	if err != nil {
		return nil, err
	}
	cs, err := f.conds(m, append(append([]Where(nil), where...), Where{Field: "id", Value: first["id"]}))
	if err != nil {
		return nil, err
	}
	if len(set) > 0 {
		if _, err := f.b.Update(ctx, m.Table(), cs, set); err != nil {
			return nil, f.wrapUnique(m, err)
		}
	}
	// Step 3: read it back by id
	return f.FindOne(ctx, model, []Where{{Field: "id", Value: first["id"]}})
}

// UpdateMany changes every matching record.
func (f *factory) UpdateMany(ctx context.Context, model string, where []Where, data Record) (int64, error) {
	m, err := f.model(model)
	if err != nil {
		return 0, err
	}
	set, err := f.updateSet(m, data)
	if err != nil {
		return 0, err
	}
	cs, err := f.conds(m, where)
	if err != nil {
		return 0, err
	}
	if len(set) == 0 {
		return f.b.Count(ctx, m.Table(), cs)
	}
	n, err := f.b.Update(ctx, m.Table(), cs, set)
	if err != nil {
		return 0, f.wrapUnique(m, err)
	}
	return n, nil
}

// Delete removes the first matching record.
func (f *factory) Delete(ctx context.Context, model string, where []Where) error {
	m, err := f.model(model)
	if err != nil {
		return err
	}
	first, err := f.FindOne(ctx, model, where, "id")
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	cs, err := f.conds(m, []Where{{Field: "id", Value: first["id"]}})
	if err != nil {
		return err
	}
	_, err = f.b.Delete(ctx, m.Table(), cs)
	return err
}

// DeleteMany removes every matching record.
func (f *factory) DeleteMany(ctx context.Context, model string, where []Where) (int64, error) {
	m, err := f.model(model)
	if err != nil {
		return 0, err
	}
	cs, err := f.conds(m, where)
	if err != nil {
		return 0, err
	}
	return f.b.Delete(ctx, m.Table(), cs)
}

// Transaction delegates to the backend.
func (f *factory) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return f.b.Transaction(ctx, fn)
}

// wrapUnique fills the model and logical fields of a backend *UniqueError.
func (f *factory) wrapUnique(m *schema.ResolvedModel, err error) error {
	var ue *UniqueError
	if !errors.As(err, &ue) {
		return err
	}
	out := &UniqueError{Model: m.Name(), Columns: ue.Columns, Err: ue.Err}
	for _, c := range ue.Columns {
		if fld, ok := m.FieldByColumn(c); ok {
			out.Fields = append(out.Fields, fld.Name)
		}
	}
	return out
}
