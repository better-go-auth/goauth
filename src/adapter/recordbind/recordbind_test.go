package recordbind_test

import (
	"context"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/adapter/memory"
	"github.com/better-go-auth/goauth/src/adapter/recordbind"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/stretchr/testify/require"
)

type status string

type doc map[string][]string

type widget struct {
	ID        string
	Name      string
	Status    status
	Enabled   bool
	Count     int64
	Note      *string
	Doc       doc
	Tags      []string
	CreatedAt time.Time
	SeenAt    *time.Time
	Missing   string
}

func registry(t *testing.T, ids schema.IDStrategy) *schema.Registry {
	t.Helper()
	reg, err := schema.Build(schema.Options{IDs: ids, Plugins: []schema.Plugin{{ID: "widgets", Schema: schema.PluginSchema{
		"widget": {Fields: map[string]schema.Field{
			"name":      {Type: schema.String, Required: true},
			"status":    {Type: schema.String, Required: true, Default: "active"},
			"enabled":   {Type: schema.Boolean, Default: true},
			"count":     {Type: schema.Number},
			"note":      {Type: schema.String},
			"doc":       {Type: schema.String},
			"tags":      {Type: schema.String},
			"createdAt": {Type: schema.Date, Default: func() any { return time.Now() }},
			"seenAt":    {Type: schema.Date},
		}},
	}}}})
	require.NoError(t, err)
	return reg
}

func binding(t *testing.T, reg *schema.Registry) *recordbind.Binding[widget] {
	t.Helper()
	return recordbind.MustNew[widget](reg, "widget",
		recordbind.Field{Go: "ID", Name: "id"},
		recordbind.Field{Go: "Name", Name: "name"},
		recordbind.Field{Go: "Status", Name: "status"},
		recordbind.Field{Go: "Enabled", Name: "enabled"},
		recordbind.Field{Go: "Count", Name: "count"},
		recordbind.Field{Go: "Note", Name: "note"},
		recordbind.Field{Go: "Doc", Name: "doc", JSON: true},
		recordbind.Field{Go: "Tags", Name: "tags", JSON: true},
		recordbind.Field{Go: "CreatedAt", Name: "createdAt"},
		recordbind.Field{Go: "SeenAt", Name: "seenAt"},
		// a Go field whose registry field doesn't exist (an optional plugin field turned off)
		recordbind.Field{Go: "Missing", Name: "missing"},
	)
}

func TestRecordRoundTrip(t *testing.T) {
	ctx := context.Background()
	reg := registry(t, "")
	b := binding(t, reg)
	store := memory.New(reg)

	// Step 1: zero id, zero date and zero defaulted string are left to the adapter / defaults; false stays false
	w := &widget{Name: "w", Enabled: false, Count: 3, Doc: doc{"a": {"b"}}, Missing: "ignored"}
	rec := b.Record(w)
	require.NotContains(t, rec, "id")
	require.NotContains(t, rec, "createdAt")
	require.NotContains(t, rec, "status")
	require.NotContains(t, rec, "missing")
	require.Equal(t, false, rec["enabled"])
	require.Equal(t, `{"a":["b"]}`, rec["doc"])
	require.Nil(t, rec["tags"], "a nil slice is null")
	require.Nil(t, rec["note"])

	// Step 2: stored and decoded: defaults applied, every type converted back
	stored, err := store.Create(ctx, b.Model(), rec)
	require.NoError(t, err)
	got, err := b.Decode(stored)
	require.NoError(t, err)
	require.NotEmpty(t, got.ID)
	require.Equal(t, status("active"), got.Status)
	require.False(t, got.Enabled)
	require.Equal(t, int64(3), got.Count)
	require.Equal(t, doc{"a": {"b"}}, got.Doc)
	require.Nil(t, got.Tags)
	require.Nil(t, got.Note)
	require.False(t, got.CreatedAt.IsZero())
	require.Empty(t, got.Missing)
	require.True(t, b.Has("doc"))
	require.False(t, b.Has("missing"))
}

func TestUpdates(t *testing.T) {
	b := binding(t, registry(t, ""))
	note := "n"
	seen := time.Now()

	// Step 1: Go names, registry names and columns; pointers and JSON values
	rec, err := b.Updates(map[string]any{"Name": "x", "status": status("off"), "note": &note, "SeenAt": &seen, "Doc": doc{"k": {"v"}}, "tags": `["raw"]`})
	require.NoError(t, err)
	require.Equal(t, adapter.Record{"name": "x", "status": status("off"), "note": &note, "seenAt": &seen, "doc": `{"k":["v"]}`, "tags": `["raw"]`}, rec)

	// Step 2: nil pointers and typed nils become null
	var none *string
	rec, err = b.Updates(map[string]any{"Note": none, "Doc": doc(nil)})
	require.NoError(t, err)
	require.Equal(t, adapter.Record{"note": nil, "doc": nil}, rec)

	// Step 3: unknown keys (and unbound fields) are errors
	_, err = b.Updates(map[string]any{"Nope": 1})
	require.Error(t, err)
	_, err = b.Updates(map[string]any{"Missing": "x"})
	require.Error(t, err)
}

func TestDecodeSerialIDs(t *testing.T) {
	reg := registry(t, schema.IDSerial)
	b := binding(t, reg)
	// ids and numbers come back as int64 / float64 / numeric strings depending on the backend
	for _, id := range []any{int64(7), float64(7), "7"} {
		got, err := b.Decode(adapter.Record{"id": id, "name": "n", "count": "12"})
		require.NoError(t, err)
		require.Equal(t, "7", got.ID)
		require.Equal(t, int64(12), got.Count)
	}
	_, err := b.Decode(adapter.Record{"count": "not a number"})
	require.Error(t, err)
	_, err = b.Decode(adapter.Record{"doc": "{broken"})
	require.Error(t, err)
}

func TestNewErrors(t *testing.T) {
	reg := registry(t, "")
	_, err := recordbind.New[widget](reg, "nope")
	require.Error(t, err)
	_, err = recordbind.New[widget](reg, "widget", recordbind.Field{Go: "NoSuchField", Name: "name"})
	require.Error(t, err)
	_, err = recordbind.New[string](reg, "widget")
	require.Error(t, err)
}
