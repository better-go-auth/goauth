// Package adaptertest is the contract every adapter.Adapter must pass (memory, GORM on SQLite / Postgres /
// MySQL, later database/sql and MongoDB). Run it from a backend's tests:
//
//	adaptertest.Run(t, func(t *testing.T, reg *schema.Registry) adapter.Adapter { ... }, adaptertest.Config{})
package adaptertest

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/stretchr/testify/require"
)

// Widget is the test model of the contract; it covers every logical type.
const Widget = "widget"

// Factory returns an adapter on fresh, empty storage that has every table of reg.
type Factory func(t *testing.T, reg *schema.Registry) adapter.Adapter

// Config adapts the contract to a backend.
type Config struct {
	// TablePrefix isolates the contract's tables on a shared database (e.g. CI's TEST_POSTGRES_URL).
	TablePrefix string
	// CaseInsensitiveEquality is set for backends whose plain Eq ignores case (MySQL's default collations);
	// the contract then skips the "Eq is case-sensitive" check.
	CaseInsensitiveEquality bool
	// SkipConcurrency skips the concurrent compare-and-swap check.
	SkipConcurrency bool
	// IDLength is the length of generated ids (0 = 32, better-auth's random ids; MongoDB's ObjectId hex
	// strings have 24).
	IDLength int
	// NonAtomicTransactions is set for backends whose Transaction can't roll back (MongoDB without a
	// replica set): the contract then skips the rollback checks.
	NonAtomicTransactions bool
}

// Registry returns the registry the contract runs on: the core models (with a config additionalField on
// user) plus the widget model.
func Registry(prefix string) *schema.Registry {
	return schema.MustBuild(schema.Options{
		TablePrefix: prefix,
		Models: map[string]schema.ModelOptions{
			schema.ModelUser: {AdditionalFields: map[string]schema.Field{
				"loyaltyTier": {Type: schema.String, Default: "bronze"},
				"birthday":    {Type: schema.Date},
			}},
		},
		Plugins: []schema.Plugin{{ID: "adaptertest", Schema: schema.PluginSchema{
			Widget: {Fields: map[string]schema.Field{
				"name":      {Type: schema.String, Required: true, Sortable: true},
				"slug":      {Type: schema.String, Required: true, Unique: true},
				"code":      {Type: schema.String, Unique: true},
				"score":     {Type: schema.Number},
				"count":     {Type: schema.Integer},
				"active":    {Type: schema.Boolean, Default: false},
				"seenAt":    {Type: schema.Date},
				"meta":      {Type: schema.JSON},
				"tags":      {Type: schema.StringArray},
				"nums":      {Type: schema.NumberArray},
				"group":     {Type: schema.String},
				"position":  {Type: schema.Integer},
				"label":     {Type: schema.String, TransformIn: lowerString, TransformOut: tagOut},
				"createdAt": {Type: schema.Date, Required: true, Default: func() any { return time.Now() }},
				"updatedAt": {Type: schema.Date, Required: true, Default: func() any { return time.Now() }, OnUpdate: func() any { return time.Now() }},
			}, Indexes: []schema.Index{{Name: "idx_widget_group_position", Fields: []string{"group", "position"}, Unique: true}}},
		}}},
	})
}

func lowerString(v any) any {
	if s, ok := v.(string); ok {
		return strings.ToLower(s)
	}
	return v
}

func tagOut(v any) any {
	if s, ok := v.(string); ok {
		return "out:" + s
	}
	return v
}

// Run executes the contract.
func Run(t *testing.T, newAdapter Factory, cfg Config) {
	reg := Registry(cfg.TablePrefix)
	tests := []struct {
		name string
		fn   func(t *testing.T, a adapter.Adapter, cfg Config)
	}{
		{"create and find", testCreateFind},
		{"nulls", testNulls},
		{"unique", testUnique},
		{"operators", testOperators},
		{"like escaping", testLikeEscaping},
		{"sort limit offset select", testQuery},
		{"update", testUpdate},
		{"compare and swap", testCAS},
		{"delete", testDelete},
		{"transactions", testTransactions},
		{"dates", testDates},
		{"json and arrays", testJSONArrays},
		{"core models and extra fields", testCoreExtra},
		{"errors", testErrors},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { tc.fn(t, newAdapter(t, reg), cfg) })
	}
}

// widget creates a widget with the required fields plus extra.
func widget(t *testing.T, a adapter.Adapter, slug string, extra adapter.Record) adapter.Record {
	t.Helper()
	data := adapter.Record{"name": "w-" + slug, "slug": slug}
	for k, v := range extra {
		data[k] = v
	}
	rec, err := a.Create(context.Background(), Widget, data)
	require.NoError(t, err)
	return rec
}

func slugs(recs []adapter.Record) []string {
	out := make([]string, len(recs))
	for i, r := range recs {
		out[i], _ = r["slug"].(string)
	}
	return out
}

func testCreateFind(t *testing.T, a adapter.Adapter, cfg Config) {
	ctx := context.Background()
	// Step 1: create generates an id and applies defaults
	before := time.Now().Add(-time.Second)
	rec := widget(t, a, "first", adapter.Record{"score": 1.5, "count": 3})
	id, _ := rec["id"].(string)
	idLen := cfg.IDLength
	if idLen == 0 {
		idLen = 32
	}
	require.Len(t, id, idLen, "generated ids")
	require.Equal(t, false, rec["active"])
	require.Equal(t, 1.5, rec["score"])
	require.Equal(t, int64(3), rec["count"])
	created, ok := rec["createdAt"].(time.Time)
	require.True(t, ok, "%T", rec["createdAt"])
	require.True(t, created.After(before))
	require.Equal(t, time.UTC, created.Location())

	// Step 2: an explicit id is kept
	explicit, err := a.Create(ctx, Widget, adapter.Record{"id": "my-id", "name": "n", "slug": "explicit"})
	require.NoError(t, err)
	require.Equal(t, "my-id", explicit["id"])

	// Step 3: find by id, by unique field, with a selection
	got, err := a.FindOne(ctx, Widget, []adapter.Where{{Field: "id", Value: id}})
	require.NoError(t, err)
	require.Equal(t, "w-first", got["name"])
	got, err = a.FindOne(ctx, Widget, []adapter.Where{{Field: "slug", Value: "first"}}, "id", "name")
	require.NoError(t, err)
	require.Equal(t, adapter.Record{"id": id, "name": "w-first"}, got)

	// Step 4: no match is ErrNotFound; FindMany returns an empty list
	_, err = a.FindOne(ctx, Widget, []adapter.Where{{Field: "slug", Value: "missing"}})
	require.ErrorIs(t, err, adapter.ErrNotFound)
	many, err := a.FindMany(ctx, Widget, adapter.Query{Where: []adapter.Where{{Field: "slug", Value: "missing"}}})
	require.NoError(t, err)
	require.Empty(t, many)
	n, err := a.Count(ctx, Widget, nil)
	require.NoError(t, err)
	require.EqualValues(t, 2, n)

	// Step 5: transforms run on the way in and out
	labeled := widget(t, a, "labeled", adapter.Record{"label": "MiXeD"})
	require.Equal(t, "out:mixed", labeled["label"])
}

func testNulls(t *testing.T, a adapter.Adapter, _ Config) {
	ctx := context.Background()
	// Step 1: optional fields left out or set to nil read back as nil
	rec := widget(t, a, "a", nil)
	for _, f := range []string{"code", "score", "count", "seenAt", "meta", "tags", "nums"} {
		require.Contains(t, rec, f)
		require.Nil(t, rec[f], f)
	}
	widget(t, a, "b", adapter.Record{"code": "B", "score": nil})
	widget(t, a, "c", adapter.Record{"code": "C"})

	// Step 2: Eq / Ne nil are IS NULL / IS NOT NULL
	isNull, err := a.FindMany(ctx, Widget, adapter.Query{Where: []adapter.Where{{Field: "code", Value: nil}}})
	require.NoError(t, err)
	require.Equal(t, []string{"a"}, slugs(isNull))
	notNull, err := a.Count(ctx, Widget, []adapter.Where{{Field: "code", Op: adapter.Ne, Value: nil}})
	require.NoError(t, err)
	require.EqualValues(t, 2, notNull)

	// Step 3: comparisons never match NULL (SQL semantics)
	ne, err := a.FindMany(ctx, Widget, adapter.Query{Where: []adapter.Where{{Field: "code", Op: adapter.Ne, Value: "B"}}})
	require.NoError(t, err)
	require.Equal(t, []string{"c"}, slugs(ne))
	notIn, err := a.Count(ctx, Widget, []adapter.Where{{Field: "code", Op: adapter.NotIn, Value: []string{"B"}}})
	require.NoError(t, err)
	require.EqualValues(t, 1, notIn)

	// Step 4: setting a value back to nil
	_, err = a.Update(ctx, Widget, []adapter.Where{{Field: "slug", Value: "c"}}, adapter.Record{"code": nil})
	require.NoError(t, err)
	n, err := a.Count(ctx, Widget, []adapter.Where{{Field: "code", Value: nil}})
	require.NoError(t, err)
	require.EqualValues(t, 2, n)
}

func testUnique(t *testing.T, a adapter.Adapter, _ Config) {
	ctx := context.Background()
	widget(t, a, "one", adapter.Record{"code": "X", "group": "g", "position": 1})
	widget(t, a, "two", adapter.Record{"group": "g", "position": 2})

	// Step 1: duplicate unique field on create
	_, err := a.Create(ctx, Widget, adapter.Record{"name": "n", "slug": "one"})
	require.ErrorIs(t, err, adapter.ErrUniqueViolation)
	var ue *adapter.UniqueError
	require.True(t, errors.As(err, &ue))
	require.Equal(t, Widget, ue.Model)

	// Step 2: nullable unique: many NULLs are fine, a duplicate value is not
	widget(t, a, "three", nil)
	widget(t, a, "four", nil)
	_, err = a.Create(ctx, Widget, adapter.Record{"name": "n", "slug": "five", "code": "X"})
	require.ErrorIs(t, err, adapter.ErrUniqueViolation)

	// Step 3: unique multi-column index (a NULL in it never conflicts)
	_, err = a.Create(ctx, Widget, adapter.Record{"name": "n", "slug": "six", "group": "g", "position": 1})
	require.ErrorIs(t, err, adapter.ErrUniqueViolation)
	widget(t, a, "seven", adapter.Record{"group": "h", "position": 1})
	widget(t, a, "eight", adapter.Record{"position": 1})
	widget(t, a, "nine", adapter.Record{"position": 1})

	// Step 4: updates are checked too, and a failed update changes nothing
	_, err = a.Update(ctx, Widget, []adapter.Where{{Field: "slug", Value: "two"}}, adapter.Record{"code": "X"})
	require.ErrorIs(t, err, adapter.ErrUniqueViolation)
	_, err = a.UpdateMany(ctx, Widget, []adapter.Where{{Field: "slug", Value: "two"}}, adapter.Record{"slug": "one"})
	require.ErrorIs(t, err, adapter.ErrUniqueViolation)
	two, err := a.FindOne(ctx, Widget, []adapter.Where{{Field: "slug", Value: "two"}})
	require.NoError(t, err)
	require.Nil(t, two["code"])
}

func testOperators(t *testing.T, a adapter.Adapter, cfg Config) {
	ctx := context.Background()
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, s := range []string{"Alpha", "beta", "Gamma", "delta"} {
		widget(t, a, strings.ToLower(s), adapter.Record{"name": s, "score": float64(i), "count": i * 10, "active": i%2 == 0, "seenAt": base.Add(time.Duration(i) * time.Hour)})
	}
	find := func(where ...adapter.Where) []string {
		t.Helper()
		recs, err := a.FindMany(ctx, Widget, adapter.Query{Where: where, Sort: []adapter.SortBy{{Field: "slug"}}})
		require.NoError(t, err)
		return slugs(recs)
	}
	// Step 1: comparisons on numbers, integers, booleans and dates
	require.Equal(t, []string{"alpha", "beta"}, find(adapter.Where{Field: "score", Op: adapter.Lt, Value: 2}))
	require.Equal(t, []string{"alpha", "beta", "gamma"}, find(adapter.Where{Field: "score", Op: adapter.Lte, Value: 2.0}))
	require.Equal(t, []string{"delta"}, find(adapter.Where{Field: "count", Op: adapter.Gt, Value: 20}))
	require.Equal(t, []string{"delta", "gamma"}, find(adapter.Where{Field: "count", Op: adapter.Gte, Value: "20"}), "numeric strings are numbers")
	require.Equal(t, []string{"alpha", "gamma"}, find(adapter.Where{Field: "active", Value: true}))
	require.Equal(t, []string{"beta", "delta"}, find(adapter.Where{Field: "active", Value: "false"}), "boolean strings are booleans")
	require.Equal(t, []string{"delta", "gamma"}, find(adapter.Where{Field: "seenAt", Op: adapter.Gte, Value: base.Add(2 * time.Hour)}))
	require.Equal(t, []string{"alpha"}, find(adapter.Where{Field: "seenAt", Op: adapter.Lt, Value: base.Add(time.Hour).In(time.FixedZone("x", 7200))}))
	require.Equal(t, []string{"alpha", "beta", "gamma"}, find(adapter.Where{Field: "slug", Op: adapter.Ne, Value: "delta"}))

	// Step 2: in / not in, empty lists included
	require.Equal(t, []string{"alpha", "delta"}, find(adapter.Where{Field: "slug", Op: adapter.In, Value: []string{"alpha", "delta", "zeta"}}))
	require.Equal(t, []string{"beta", "gamma"}, find(adapter.Where{Field: "slug", Op: adapter.NotIn, Value: []any{"alpha", "delta"}}))
	require.Empty(t, find(adapter.Where{Field: "slug", Op: adapter.In, Value: []string{}}))
	require.Len(t, find(adapter.Where{Field: "slug", Op: adapter.NotIn, Value: []string{}}), 4)
	require.Equal(t, []string{"beta", "gamma"}, find(adapter.Where{Field: "count", Op: adapter.In, Value: []int{10, 20}}))

	// Step 3: string patterns, case-sensitive and insensitive
	require.Equal(t, []string{"alpha", "gamma"}, find(adapter.Where{Field: "name", Op: adapter.Contains, Value: "mm", Connector: adapter.Or}, adapter.Where{Field: "name", Op: adapter.StartsWith, Value: "A", Connector: adapter.Or}))
	require.Equal(t, []string{"gamma"}, find(adapter.Where{Field: "name", Op: adapter.StartsWith, Value: "Ga"}))
	require.Empty(t, find(adapter.Where{Field: "name", Op: adapter.StartsWith, Value: "ga"}), "patterns are case-sensitive by default")
	require.Equal(t, []string{"gamma"}, find(adapter.Where{Field: "name", Op: adapter.StartsWith, Value: "ga", Insensitive: true}))
	require.Equal(t, []string{"alpha", "beta", "delta", "gamma"}, find(adapter.Where{Field: "name", Op: adapter.EndsWith, Value: "A", Insensitive: true}))
	require.Equal(t, []string{"delta"}, find(adapter.Where{Field: "name", Op: adapter.Contains, Value: "ELT", Insensitive: true}))
	require.Equal(t, []string{"alpha"}, find(adapter.Where{Field: "name", Value: "ALPHA", Insensitive: true}))
	require.Equal(t, []string{"alpha", "beta"}, find(adapter.Where{Field: "name", Op: adapter.In, Value: []string{"ALPHA", "BETA"}, Insensitive: true}))
	if !cfg.CaseInsensitiveEquality {
		require.Empty(t, find(adapter.Where{Field: "name", Value: "ALPHA"}), "Eq is case-sensitive by default")
	}

	// Step 4: connectors: (all And) AND (any Or)
	require.Equal(t, []string{"alpha", "gamma"}, find(
		adapter.Where{Field: "active", Value: true},
		adapter.Where{Field: "slug", Value: "alpha", Connector: adapter.Or},
		adapter.Where{Field: "slug", Value: "gamma", Connector: adapter.Or},
		adapter.Where{Field: "slug", Value: "beta", Connector: adapter.Or},
	))
	require.Equal(t, []string{"beta", "delta"}, find(
		adapter.Where{Field: "slug", Value: "beta", Connector: adapter.Or},
		adapter.Where{Field: "slug", Value: "delta", Connector: adapter.Or},
	))
}

func testLikeEscaping(t *testing.T, a adapter.Adapter, _ Config) {
	ctx := context.Background()
	for slug, name := range map[string]string{"pct": "100% sure", "plain": "1000 sure", "under": "a_b", "nounder": "axb", "bang": "wow!", "glob": "[x]*?", "globless": "x"} {
		widget(t, a, slug, adapter.Record{"name": name})
	}
	find := func(op adapter.Op, v string, insensitive bool) []string {
		t.Helper()
		recs, err := a.FindMany(ctx, Widget, adapter.Query{Where: []adapter.Where{{Field: "name", Op: op, Value: v, Insensitive: insensitive}}, Sort: []adapter.SortBy{{Field: "slug"}}})
		require.NoError(t, err)
		return slugs(recs)
	}
	// Step 1: % and _ match themselves, not any character
	for _, insensitive := range []bool{false, true} {
		require.Equal(t, []string{"pct"}, find(adapter.Contains, "0%", insensitive))
		require.Equal(t, []string{"under"}, find(adapter.Contains, "_", insensitive))
		require.Equal(t, []string{"bang"}, find(adapter.EndsWith, "!", insensitive))
		require.Equal(t, []string{"glob"}, find(adapter.StartsWith, "[x]*", insensitive))
		require.Equal(t, []string{"glob"}, find(adapter.Contains, "?", insensitive))
	}
}

func testQuery(t *testing.T, a adapter.Adapter, _ Config) {
	ctx := context.Background()
	for i, s := range []string{"c", "a", "d", "b", "e"} {
		widget(t, a, s, adapter.Record{"score": float64(i % 2)})
	}
	// Step 1: sort ascending/descending and by several fields
	recs, err := a.FindMany(ctx, Widget, adapter.Query{Sort: []adapter.SortBy{{Field: "slug", Desc: true}}})
	require.NoError(t, err)
	require.Equal(t, []string{"e", "d", "c", "b", "a"}, slugs(recs))
	recs, err = a.FindMany(ctx, Widget, adapter.Query{Sort: []adapter.SortBy{{Field: "score"}, {Field: "slug", Desc: true}}})
	require.NoError(t, err)
	require.Equal(t, []string{"e", "d", "c", "b", "a"}, slugs(recs))
	recs, err = a.FindMany(ctx, Widget, adapter.Query{Sort: []adapter.SortBy{{Field: "score", Desc: true}, {Field: "slug"}}})
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b", "c", "d", "e"}, slugs(recs))

	// Step 2: limit and offset
	recs, err = a.FindMany(ctx, Widget, adapter.Query{Sort: []adapter.SortBy{{Field: "slug"}}, Limit: 2, Offset: 1})
	require.NoError(t, err)
	require.Equal(t, []string{"b", "c"}, slugs(recs))
	recs, err = a.FindMany(ctx, Widget, adapter.Query{Sort: []adapter.SortBy{{Field: "slug"}}, Limit: 10, Offset: 4})
	require.NoError(t, err)
	require.Equal(t, []string{"e"}, slugs(recs))
	recs, err = a.FindMany(ctx, Widget, adapter.Query{Sort: []adapter.SortBy{{Field: "slug"}}, Limit: 10, Offset: 9})
	require.NoError(t, err)
	require.Empty(t, recs)

	// Step 3: select returns only the requested fields
	recs, err = a.FindMany(ctx, Widget, adapter.Query{Where: []adapter.Where{{Field: "slug", Value: "a"}}, Select: []string{"slug", "score"}})
	require.NoError(t, err)
	require.Equal(t, []adapter.Record{{"slug": "a", "score": 1.0}}, recs)

	// Step 4: count with conditions
	n, err := a.Count(ctx, Widget, []adapter.Where{{Field: "score", Value: 0}})
	require.NoError(t, err)
	require.EqualValues(t, 3, n)
}

func testUpdate(t *testing.T, a adapter.Adapter, _ Config) {
	ctx := context.Background()
	rec := widget(t, a, "u", adapter.Record{"score": 1})
	widget(t, a, "v", adapter.Record{"score": 1})
	time.Sleep(5 * time.Millisecond)

	// Step 1: Update returns the updated record and refreshes OnUpdate fields
	up, err := a.Update(ctx, Widget, []adapter.Where{{Field: "slug", Value: "u"}}, adapter.Record{"name": "renamed", "score": 2.5, "label": "UP"})
	require.NoError(t, err)
	require.Equal(t, "renamed", up["name"])
	require.Equal(t, 2.5, up["score"])
	require.Equal(t, "out:up", up["label"])
	require.True(t, up["updatedAt"].(time.Time).After(rec["updatedAt"].(time.Time)), "updatedAt moves")
	require.Equal(t, rec["createdAt"], up["createdAt"])

	// Step 2: Update changes only the first match; UpdateMany changes all and counts them
	n, err := a.UpdateMany(ctx, Widget, []adapter.Where{{Field: "score", Op: adapter.Gte, Value: 1}}, adapter.Record{"active": true})
	require.NoError(t, err)
	require.EqualValues(t, 2, n)
	n, err = a.Count(ctx, Widget, []adapter.Where{{Field: "active", Value: true}})
	require.NoError(t, err)
	require.EqualValues(t, 2, n)

	// Step 3: no match
	_, err = a.Update(ctx, Widget, []adapter.Where{{Field: "slug", Value: "missing"}}, adapter.Record{"name": "x"})
	require.ErrorIs(t, err, adapter.ErrNotFound)
	n, err = a.UpdateMany(ctx, Widget, []adapter.Where{{Field: "slug", Value: "missing"}}, adapter.Record{"name": "x"})
	require.NoError(t, err)
	require.Zero(t, n)
}

func testCAS(t *testing.T, a adapter.Adapter, cfg Config) {
	ctx := context.Background()
	rec := widget(t, a, "cas", adapter.Record{"name": "v0"})
	id := rec["id"]
	swap := func(from, to string) int64 {
		n, err := a.UpdateMany(ctx, Widget, []adapter.Where{{Field: "id", Value: id}, {Field: "name", Value: from}}, adapter.Record{"name": to})
		require.NoError(t, err)
		return n
	}
	// Step 1: the swap only succeeds from the current value
	require.EqualValues(t, 1, swap("v0", "v1"))
	require.EqualValues(t, 0, swap("v0", "v1"))
	// Step 2: compare-and-delete
	n, err := a.DeleteMany(ctx, Widget, []adapter.Where{{Field: "id", Value: id}, {Field: "name", Value: "v0"}})
	require.NoError(t, err)
	require.Zero(t, n)

	// Step 3: concurrent swaps from the same snapshot: exactly one wins
	if cfg.SkipConcurrency {
		return
	}
	var wins int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := a.UpdateMany(ctx, Widget, []adapter.Where{{Field: "id", Value: id}, {Field: "name", Value: "v1"}}, adapter.Record{"name": "v2"})
			if err == nil && n == 1 {
				atomic.AddInt32(&wins, 1)
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 1, wins)
	n, err = a.DeleteMany(ctx, Widget, []adapter.Where{{Field: "id", Value: id}, {Field: "name", Value: "v2"}})
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
}

func testDelete(t *testing.T, a adapter.Adapter, _ Config) {
	ctx := context.Background()
	for _, s := range []string{"a", "b", "c", "d"} {
		widget(t, a, s, adapter.Record{"score": 1})
	}
	// Step 1: Delete removes only the first match and ignores no match
	require.NoError(t, a.Delete(ctx, Widget, []adapter.Where{{Field: "score", Value: 1}}))
	n, err := a.Count(ctx, Widget, nil)
	require.NoError(t, err)
	require.EqualValues(t, 3, n)
	require.NoError(t, a.Delete(ctx, Widget, []adapter.Where{{Field: "slug", Value: "missing"}}))

	// Step 2: DeleteMany counts
	n, err = a.DeleteMany(ctx, Widget, []adapter.Where{{Field: "slug", Op: adapter.In, Value: []string{"c", "d", "x"}}})
	require.NoError(t, err)
	remaining, _ := a.Count(ctx, Widget, nil)
	require.EqualValues(t, 3-remaining, n)
	n, err = a.DeleteMany(ctx, Widget, nil)
	require.NoError(t, err)
	require.EqualValues(t, remaining, n)
	remaining, _ = a.Count(ctx, Widget, nil)
	require.Zero(t, remaining)
}

func testTransactions(t *testing.T, a adapter.Adapter, cfg Config) {
	ctx := context.Background()
	boom := errors.New("boom")
	keep := widget(t, a, "keep", adapter.Record{"score": 1})
	if cfg.NonAtomicTransactions {
		// Step 0: without atomicity, Transaction still runs fn with a ctx that works and returns its error
		err := a.Transaction(ctx, func(ctx context.Context) error {
			_, err := a.Create(ctx, Widget, adapter.Record{"name": "n", "slug": "non-atomic"})
			if err != nil {
				return err
			}
			return boom
		})
		require.ErrorIs(t, err, boom)
		_, err = a.FindOne(ctx, Widget, []adapter.Where{{Field: "slug", Value: "non-atomic"}})
		require.NoError(t, err, "a non-atomic transaction keeps its writes")
		return
	}

	// Step 1: an error rolls back every write, nested transactions included
	err := a.Transaction(ctx, func(ctx context.Context) error {
		if _, err := a.Create(ctx, Widget, adapter.Record{"name": "n", "slug": "rolled-back"}); err != nil {
			return err
		}
		if _, err := a.Update(ctx, Widget, []adapter.Where{{Field: "id", Value: keep["id"]}}, adapter.Record{"score": 99}); err != nil {
			return err
		}
		// reads inside the transaction see its writes
		n, err := a.Count(ctx, Widget, []adapter.Where{{Field: "slug", Value: "rolled-back"}})
		if err != nil || n != 1 {
			return errors.New("transaction can't read its own write")
		}
		return a.Transaction(ctx, func(ctx context.Context) error {
			_, err := a.DeleteMany(ctx, Widget, []adapter.Where{{Field: "slug", Value: "keep"}})
			if err != nil {
				return err
			}
			return boom
		})
	})
	require.ErrorIs(t, err, boom)
	_, err = a.FindOne(ctx, Widget, []adapter.Where{{Field: "slug", Value: "rolled-back"}})
	require.ErrorIs(t, err, adapter.ErrNotFound)
	got, err := a.FindOne(ctx, Widget, []adapter.Where{{Field: "slug", Value: "keep"}})
	require.NoError(t, err)
	require.Equal(t, 1.0, got["score"])

	// Step 2: success commits
	require.NoError(t, a.Transaction(ctx, func(ctx context.Context) error {
		_, err := a.Create(ctx, Widget, adapter.Record{"name": "n", "slug": "committed"})
		return err
	}))
	_, err = a.FindOne(ctx, Widget, []adapter.Where{{Field: "slug", Value: "committed"}})
	require.NoError(t, err)

	// Step 3: a unique violation inside a transaction surfaces as such and rolls back
	err = a.Transaction(ctx, func(ctx context.Context) error {
		if _, err := a.Create(ctx, Widget, adapter.Record{"name": "n", "slug": "tx-a"}); err != nil {
			return err
		}
		_, err := a.Create(ctx, Widget, adapter.Record{"name": "n", "slug": "committed"})
		return err
	})
	require.ErrorIs(t, err, adapter.ErrUniqueViolation)
	_, err = a.FindOne(ctx, Widget, []adapter.Where{{Field: "slug", Value: "tx-a"}})
	require.ErrorIs(t, err, adapter.ErrNotFound)
}

func testDates(t *testing.T, a adapter.Adapter, _ Config) {
	ctx := context.Background()
	// Step 1: any zone in, UTC with millisecond precision out
	in := time.Date(2030, 6, 7, 8, 9, 10, 123456789, time.FixedZone("CEST", 2*3600))
	rec := widget(t, a, "d", adapter.Record{"seenAt": in})
	want := time.Date(2030, 6, 7, 6, 9, 10, 123000000, time.UTC)
	require.Equal(t, want, rec["seenAt"])
	got, err := a.FindOne(ctx, Widget, []adapter.Where{{Field: "seenAt", Value: in}})
	require.NoError(t, err, "a date finds itself despite sub-millisecond digits")
	require.Equal(t, want, got["seenAt"])

	// Step 2: RFC 3339 strings are dates
	rec = widget(t, a, "s", adapter.Record{"seenAt": "2030-06-07T06:09:10.5Z"})
	require.Equal(t, time.Date(2030, 6, 7, 6, 9, 10, 500000000, time.UTC), rec["seenAt"])
	n, err := a.Count(ctx, Widget, []adapter.Where{{Field: "seenAt", Op: adapter.Gt, Value: "2030-06-07T06:09:10.2Z"}})
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
}

func testJSONArrays(t *testing.T, a adapter.Adapter, _ Config) {
	ctx := context.Background()
	// Step 1: json, string[] and number[] round-trip
	rec := widget(t, a, "j", adapter.Record{
		"meta": map[string]any{"plan": "pro", "seats": 3, "flags": []any{true, nil}},
		"tags": []string{"a", "b"},
		"nums": []any{1, 2.5},
	})
	got, err := a.FindOne(ctx, Widget, []adapter.Where{{Field: "id", Value: rec["id"]}})
	require.NoError(t, err)
	raw, ok := got["meta"].(json.RawMessage)
	require.True(t, ok, "%T", got["meta"])
	require.JSONEq(t, `{"plan":"pro","seats":3,"flags":[true,null]}`, string(raw))
	require.Equal(t, []string{"a", "b"}, got["tags"])
	require.Equal(t, []float64{1, 2.5}, got["nums"])

	// Step 2: update them; empty arrays stay empty (not nil)
	up, err := a.Update(ctx, Widget, []adapter.Where{{Field: "id", Value: rec["id"]}}, adapter.Record{"meta": json.RawMessage(`[1,2]`), "tags": []string{}})
	require.NoError(t, err)
	require.JSONEq(t, `[1,2]`, string(up["meta"].(json.RawMessage)))
	require.Equal(t, []string{}, up["tags"])

	// Step 3: a value of the wrong type is a *ValueError
	_, err = a.Create(ctx, Widget, adapter.Record{"name": "n", "slug": "bad", "tags": "a,b"})
	var ve *adapter.ValueError
	require.True(t, errors.As(err, &ve), "%v", err)
	require.Equal(t, "tags", ve.Field)
}

func testCoreExtra(t *testing.T, a adapter.Adapter, _ Config) {
	ctx := context.Background()
	birthday := time.Date(1990, 1, 2, 0, 0, 0, 0, time.UTC)
	// Step 1: a core model with an additional field (default applied) and a plugin-owned column
	user, err := a.Create(ctx, schema.ModelUser, adapter.Record{"name": "Ann", "email": "ann@example.com", "birthday": birthday, "role": "admin"})
	require.NoError(t, err)
	require.Equal(t, "bronze", user["loyaltyTier"])
	require.Equal(t, birthday, user["birthday"])
	require.Equal(t, false, user["emailVerified"])
	require.Equal(t, "admin", user["role"])

	// Step 2: query and update the additional field
	got, err := a.FindOne(ctx, schema.ModelUser, []adapter.Where{{Field: "loyaltyTier", Value: "bronze"}})
	require.NoError(t, err)
	require.Equal(t, user["id"], got["id"])
	up, err := a.Update(ctx, schema.ModelUser, []adapter.Where{{Field: "id", Value: user["id"]}}, adapter.Record{"loyaltyTier": "gold", "emailVerified": true})
	require.NoError(t, err)
	require.Equal(t, "gold", up["loyaltyTier"])
	require.Equal(t, true, up["emailVerified"])

	// Step 3: a session referencing the user
	_, err = a.Create(ctx, schema.ModelSession, adapter.Record{"token": "t1", "userId": user["id"], "expiresAt": time.Now().Add(time.Hour), "updatedAt": time.Now()})
	require.NoError(t, err)
	joined, err := adapter.FindOneJoined(ctx, a, schema.ModelSession, []adapter.Where{{Field: "token", Value: "t1"}}, []adapter.Join{
		{Model: schema.ModelUser, Field: "userId", RefField: "id"},
		{Model: schema.ModelAccount, Field: "userId", RefField: "userId", Many: true},
	})
	require.NoError(t, err)
	require.Equal(t, "gold", joined[schema.ModelUser].(adapter.Record)["loyaltyTier"])
	require.Empty(t, joined[schema.ModelAccount])
}

func testErrors(t *testing.T, a adapter.Adapter, _ Config) {
	ctx := context.Background()
	// Step 1: unknown models and fields
	_, err := a.Create(ctx, "nope", adapter.Record{})
	require.ErrorIs(t, err, adapter.ErrUnknownModel)
	_, err = a.Create(ctx, Widget, adapter.Record{"name": "n", "slug": "s", "nope": 1})
	require.ErrorIs(t, err, adapter.ErrUnknownField)
	_, err = a.FindOne(ctx, Widget, []adapter.Where{{Field: "nope", Value: 1}})
	require.ErrorIs(t, err, adapter.ErrUnknownField)
	_, err = a.FindMany(ctx, Widget, adapter.Query{Sort: []adapter.SortBy{{Field: "nope"}}})
	require.ErrorIs(t, err, adapter.ErrUnknownField)
	_, err = a.UpdateMany(ctx, Widget, nil, adapter.Record{"nope": 1})
	require.ErrorIs(t, err, adapter.ErrUnknownField)

	// Step 2: required values and operator arguments
	_, err = a.Create(ctx, Widget, adapter.Record{"slug": "s"})
	var ve *adapter.ValueError
	require.True(t, errors.As(err, &ve), "%v", err)
	require.Equal(t, "name", ve.Field)
	_, err = a.Create(ctx, Widget, adapter.Record{"name": nil, "slug": "s"})
	require.True(t, errors.As(err, &ve), "%v", err)
	_, err = a.FindMany(ctx, Widget, adapter.Query{Where: []adapter.Where{{Field: "slug", Op: adapter.In, Value: "x"}}})
	require.Error(t, err)
	_, err = a.FindMany(ctx, Widget, adapter.Query{Where: []adapter.Where{{Field: "slug", Op: adapter.Contains, Value: 1}}})
	require.Error(t, err)
	_, err = a.FindMany(ctx, Widget, adapter.Query{Where: []adapter.Where{{Field: "slug", Op: "regex", Value: "x"}}})
	require.Error(t, err)
	n, err := a.Count(ctx, Widget, nil)
	require.NoError(t, err)
	require.Zero(t, n, "failed creates wrote nothing")
}
