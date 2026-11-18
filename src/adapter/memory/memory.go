// Package memory is the in-memory adapter.Backend, for tests and examples. Unique fields and unique
// indexes of the registry are enforced (NULLs never conflict, like SQL), and transactions are serialised
// with rollback.
package memory

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/schema"
)

// New returns an in-memory adapter for reg.
func New(reg *schema.Registry, opts ...adapter.Option) adapter.Adapter {
	return adapter.New(reg, NewBackend(reg), opts...)
}

// table is one in-memory table: rows in insertion order and the unique column sets.
type table struct {
	rows    []adapter.Row
	uniques [][]string
	// serial is the last auto-increment id handed out (id strategy serial)
	serial int64
}

// Backend stores rows in maps. It is safe for concurrent use.
//
// Every operation outside a transaction takes txMu (shared for reads), and a transaction holds it
// exclusively until it ends, so transactions are serialisable. Inside fn, only calls made with the ctx
// passed to fn belong to the transaction; a call with another context waits for the transaction to end.
type Backend struct {
	txMu   sync.RWMutex
	mu     sync.Mutex
	tables map[string]*table
}

var (
	_ adapter.Backend    = (*Backend)(nil)
	_ adapter.IDInserter = (*Backend)(nil)
)

// NewBackend creates empty tables for every model of reg.
func NewBackend(reg *schema.Registry) *Backend {
	b := &Backend{tables: map[string]*table{}}
	for _, m := range reg.Models() {
		t := &table{}
		// Step 1: single-column unique fields (the primary key included)
		for _, f := range m.Fields() {
			if f.Unique || f.Name == "id" {
				t.uniques = append(t.uniques, []string{f.Column})
			}
		}
		// Step 2: unique multi-column indexes
		for _, idx := range m.Indexes() {
			if !idx.Unique {
				continue
			}
			cols := make([]string, len(idx.Fields))
			for i, fn := range idx.Fields {
				cols[i] = m.Column(fn)
			}
			t.uniques = append(t.uniques, cols)
		}
		b.tables[m.Table()] = t
	}
	return b
}

// ID returns "memory".
func (b *Backend) ID() string { return "memory" }

// Capabilities: every type is stored natively.
func (b *Backend) Capabilities() adapter.Capabilities {
	return adapter.Capabilities{JSON: true, Arrays: true, Dates: true, Booleans: true}
}

type txKey struct{}

// tx marks a context as running inside this backend's transaction.
type tx struct {
	b      *Backend
	active bool
}

// lock acquires the locks for one operation and returns the unlock function.
func (b *Backend) lock(ctx context.Context, write bool) func() {
	if t, ok := ctx.Value(txKey{}).(*tx); ok && t.b == b && t.active {
		b.mu.Lock()
		return b.mu.Unlock
	}
	if write {
		b.txMu.Lock()
		b.mu.Lock()
		return func() { b.mu.Unlock(); b.txMu.Unlock() }
	}
	b.txMu.RLock()
	b.mu.Lock()
	return func() { b.mu.Unlock(); b.txMu.RUnlock() }
}

func (b *Backend) table(name string) (*table, error) {
	t, ok := b.tables[name]
	if !ok {
		return nil, fmt.Errorf("memory: no table %q", name)
	}
	return t, nil
}

// Insert adds a row after checking unique constraints.
func (b *Backend) Insert(ctx context.Context, name string, row adapter.Row) error {
	defer b.lock(ctx, true)()
	t, err := b.table(name)
	if err != nil {
		return err
	}
	if err := t.checkUnique(row, -1); err != nil {
		return err
	}
	t.rows = append(t.rows, copyRow(row))
	return nil
}

// InsertReturningID adds a row without an id, like a database creating it: the next integer for serial
// ids, else a random 32-char hex string (a database default).
func (b *Backend) InsertReturningID(ctx context.Context, name string, row adapter.Row, idColumn string, serial bool) (any, error) {
	defer b.lock(ctx, true)()
	t, err := b.table(name)
	if err != nil {
		return nil, err
	}
	// Step 1: the generated id
	row = copyRow(row)
	if serial {
		t.serial++
		row[idColumn] = t.serial
	} else {
		var buf [16]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return nil, err
		}
		row[idColumn] = hex.EncodeToString(buf[:])
	}
	// Step 2: constraints, then the insert
	if err := t.checkUnique(row, -1); err != nil {
		if serial {
			t.serial--
		}
		return nil, err
	}
	t.rows = append(t.rows, row)
	return row[idColumn], nil
}

// checkUnique reports a *adapter.UniqueError when row collides with another row (skip = its own index).
func (t *table) checkUnique(row adapter.Row, skip int) error {
	for _, cols := range t.uniques {
		// Step 1: a NULL in any column never conflicts
		hasNull := false
		for _, c := range cols {
			if row[c] == nil {
				hasNull = true
			}
		}
		if hasNull {
			continue
		}
		// Step 2: compare with every other row
		for i, other := range t.rows {
			if i == skip {
				continue
			}
			same := true
			for _, c := range cols {
				if !equal(row[c], other[c], false) {
					same = false
					break
				}
			}
			if same {
				return &adapter.UniqueError{Columns: append([]string(nil), cols...)}
			}
		}
	}
	return nil
}

// Select returns copies of the matching rows.
func (b *Backend) Select(ctx context.Context, name string, q adapter.Select) ([]adapter.Row, error) {
	defer b.lock(ctx, false)()
	t, err := b.table(name)
	if err != nil {
		return nil, err
	}
	// Step 1: filter
	var out []adapter.Row
	for _, r := range t.rows {
		if matches(r, q.Where) {
			out = append(out, r)
		}
	}
	// Step 2: sort (stable, so insertion order breaks ties)
	if len(q.Order) > 0 {
		sort.SliceStable(out, func(i, j int) bool {
			for _, o := range q.Order {
				c := compare(out[i][o.Column], out[j][o.Column])
				if c == 0 {
					continue
				}
				if o.Desc {
					return c > 0
				}
				return c < 0
			}
			return false
		})
	}
	// Step 3: offset and limit
	if q.Offset > 0 {
		if q.Offset >= len(out) {
			out = nil
		} else {
			out = out[q.Offset:]
		}
	}
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	// Step 4: copy (and project) so callers never share storage
	res := make([]adapter.Row, len(out))
	for i, r := range out {
		if len(q.Columns) == 0 {
			res[i] = copyRow(r)
			continue
		}
		p := adapter.Row{}
		for _, c := range q.Columns {
			p[c] = copyValue(r[c])
		}
		res[i] = p
	}
	return res, nil
}

// Count counts the matching rows.
func (b *Backend) Count(ctx context.Context, name string, where []adapter.Cond) (int64, error) {
	defer b.lock(ctx, false)()
	t, err := b.table(name)
	if err != nil {
		return 0, err
	}
	var n int64
	for _, r := range t.rows {
		if matches(r, where) {
			n++
		}
	}
	return n, nil
}

// Update sets columns on every matching row; nothing changes when one of them would violate a unique
// constraint.
func (b *Backend) Update(ctx context.Context, name string, where []adapter.Cond, set adapter.Row) (int64, error) {
	defer b.lock(ctx, true)()
	t, err := b.table(name)
	if err != nil {
		return 0, err
	}
	// Step 1: compute the new rows and check them
	updated := map[int]adapter.Row{}
	for i, r := range t.rows {
		if !matches(r, where) {
			continue
		}
		next := copyRow(r)
		for k, v := range set {
			next[k] = copyValue(v)
		}
		updated[i] = next
	}
	saved := t.rows
	t.rows = append([]adapter.Row(nil), saved...)
	for i, next := range updated {
		t.rows[i] = next
	}
	for i := range updated {
		if err := t.checkUnique(t.rows[i], i); err != nil {
			t.rows = saved
			return 0, err
		}
	}
	return int64(len(updated)), nil
}

// Delete removes every matching row.
func (b *Backend) Delete(ctx context.Context, name string, where []adapter.Cond) (int64, error) {
	defer b.lock(ctx, true)()
	t, err := b.table(name)
	if err != nil {
		return 0, err
	}
	kept := t.rows[:0:0]
	var n int64
	for _, r := range t.rows {
		if matches(r, where) {
			n++
			continue
		}
		kept = append(kept, r)
	}
	t.rows = kept
	return n, nil
}

// Transaction runs fn holding the transaction lock; on error (or panic) every table is restored.
func (b *Backend) Transaction(ctx context.Context, fn func(ctx context.Context) error) (err error) {
	// Step 1: nested calls join the running transaction
	if t, ok := ctx.Value(txKey{}).(*tx); ok && t.b == b && t.active {
		return fn(ctx)
	}
	// Step 2: take the transaction lock and a snapshot for rollback
	b.txMu.Lock()
	defer b.txMu.Unlock()
	b.mu.Lock()
	snapshot := b.snapshot()
	b.mu.Unlock()
	t := &tx{b: b, active: true}
	defer func() {
		t.active = false
		// Step 3: roll back on error or panic
		if r := recover(); r != nil {
			b.restore(snapshot)
			panic(r)
		}
		if err != nil {
			b.restore(snapshot)
		}
	}()
	return fn(context.WithValue(ctx, txKey{}, t))
}

func (b *Backend) snapshot() map[string][]adapter.Row {
	s := map[string][]adapter.Row{}
	for name, t := range b.tables {
		s[name] = append([]adapter.Row(nil), t.rows...)
	}
	return s
}

func (b *Backend) restore(s map[string][]adapter.Row) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for name, rows := range s {
		b.tables[name].rows = rows
	}
}

// matches evaluates conditions like SQL: (all And conditions) AND (any Or condition).
func matches(r adapter.Row, where []adapter.Cond) bool {
	anyOr, hasOr := false, false
	for _, c := range where {
		ok := matchOne(r[c.Column], c)
		if c.Connector == adapter.Or {
			hasOr = true
			anyOr = anyOr || ok
			continue
		}
		if !ok {
			return false
		}
	}
	return !hasOr || anyOr
}

// matchOne evaluates one condition. Like SQL, a NULL value only matches Eq/Ne nil.
func matchOne(v any, c adapter.Cond) bool {
	// Step 1: IS NULL / IS NOT NULL
	if c.Value == nil && (c.Op == adapter.Eq || c.Op == adapter.Ne) {
		return (v == nil) == (c.Op == adapter.Eq)
	}
	if v == nil {
		return false
	}
	// Step 2: the operators
	switch c.Op {
	case adapter.Eq:
		return equal(v, c.Value, c.Insensitive)
	case adapter.Ne:
		return !equal(v, c.Value, c.Insensitive)
	case adapter.Lt:
		return compare(v, c.Value) < 0
	case adapter.Lte:
		return compare(v, c.Value) <= 0
	case adapter.Gt:
		return compare(v, c.Value) > 0
	case adapter.Gte:
		return compare(v, c.Value) >= 0
	case adapter.In, adapter.NotIn:
		found := false
		for _, x := range c.Value.([]any) {
			if x != nil && equal(v, x, c.Insensitive) {
				found = true
				break
			}
		}
		return found == (c.Op == adapter.In)
	case adapter.Contains, adapter.StartsWith, adapter.EndsWith:
		s, ok := v.(string)
		if !ok {
			return false
		}
		p := c.Value.(string)
		if c.Insensitive {
			s, p = strings.ToLower(s), strings.ToLower(p)
		}
		switch c.Op {
		case adapter.StartsWith:
			return strings.HasPrefix(s, p)
		case adapter.EndsWith:
			return strings.HasSuffix(s, p)
		}
		return strings.Contains(s, p)
	}
	return false
}

// equal compares two stored values.
func equal(a, b any, insensitive bool) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if sa, ok := a.(string); ok {
		sb, ok := b.(string)
		if !ok {
			return false
		}
		if insensitive {
			return strings.EqualFold(sa, sb)
		}
		return sa == sb
	}
	return compare(a, b) == 0
}

// compare orders two stored values of the same kind; NULLs sort first (like SQLite and MySQL).
func compare(a, b any) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	}
	switch x := a.(type) {
	case string:
		y, _ := b.(string)
		return strings.Compare(x, y)
	case time.Time:
		y, _ := b.(time.Time)
		return x.Compare(y)
	case bool:
		y, _ := b.(bool)
		switch {
		case x == y:
			return 0
		case !x:
			return -1
		}
		return 1
	case float64, int64:
		fx, fy := toF(a), toF(b)
		switch {
		case fx < fy:
			return -1
		case fx > fy:
			return 1
		}
		return 0
	}
	// json, arrays: compare their JSON text
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return strings.Compare(string(ja), string(jb))
}

func toF(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int64:
		return float64(x)
	}
	return 0
}

func copyRow(r adapter.Row) adapter.Row {
	out := make(adapter.Row, len(r))
	for k, v := range r {
		out[k] = copyValue(v)
	}
	return out
}

// copyValue copies the mutable storage types (slices and raw JSON).
func copyValue(v any) any {
	switch x := v.(type) {
	case json.RawMessage:
		return append(json.RawMessage(nil), x...)
	case []string:
		return append([]string(nil), x...)
	case []float64:
		return append([]float64(nil), x...)
	}
	return v
}
