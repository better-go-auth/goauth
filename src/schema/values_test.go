package schema_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/schema"
	"github.com/stretchr/testify/require"
)

func TestGetSetBind(t *testing.T) {
	v := schema.Values{}
	when := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	schema.Set(v, "tier", "gold")
	schema.Set(v, "points", 12.0)
	schema.Set(v, "joined", when)
	schema.Set(v, "joinedText", "2020-01-02T03:04:05Z")
	schema.Set(v, "tags", []any{"a", "b"})
	schema.Set(v, "meta", json.RawMessage(`{"k":1}`))
	schema.Set(v, "empty", nil)

	// Step 1: Get converts between compatible representations
	tier, ok := schema.Get[string](v, "tier")
	require.True(t, ok)
	require.Equal(t, "gold", tier)
	points, ok := schema.Get[int](v, "points")
	require.True(t, ok)
	require.Equal(t, 12, points)
	joined, ok := schema.Get[time.Time](v, "joinedText")
	require.True(t, ok)
	require.True(t, when.Equal(joined))
	tags, ok := schema.Get[[]string](v, "tags")
	require.True(t, ok)
	require.Equal(t, []string{"a", "b"}, tags)
	meta, ok := schema.Get[map[string]int](v, "meta")
	require.True(t, ok)
	require.Equal(t, map[string]int{"k": 1}, meta)
	ptr, ok := schema.Get[*string](v, "tier")
	require.True(t, ok)
	require.Equal(t, "gold", *ptr)

	// Step 2: missing, nil and unconvertible values report ok=false
	_, ok = schema.Get[string](v, "missing")
	require.False(t, ok)
	_, ok = schema.Get[string](v, "empty")
	require.False(t, ok)
	_, ok = schema.Get[bool](v, "tier")
	require.False(t, ok)
	_, ok = schema.Get[string](nil, "tier")
	require.False(t, ok)

	// Step 3: Bind fills tagged struct fields
	var dst struct {
		Tier    string    `field:"tier"`
		Points  int64     `field:"points"`
		Joined  time.Time `field:"joined"`
		Missing string    `field:"missing"`
		Ignored string
	}
	dst.Missing = "keep"
	require.NoError(t, schema.Bind(v, &dst))
	require.Equal(t, "gold", dst.Tier)
	require.EqualValues(t, 12, dst.Points)
	require.Equal(t, when, dst.Joined)
	require.Equal(t, "keep", dst.Missing)
	require.Error(t, schema.Bind(v, dst), "needs a pointer")
	var bad struct {
		Tier bool `field:"tier"`
	}
	require.Error(t, schema.Bind(v, &bad))
}

func TestNormalize(t *testing.T) {
	s := "x"
	var nilPtr *string
	cases := []struct {
		t    schema.FieldType
		in   any
		want any
	}{
		{schema.String, &s, "x"},
		{schema.String, nilPtr, nil},
		{schema.String, nil, nil},
		{schema.Number, 3, 3.0},
		{schema.Number, json.Number("2.5"), 2.5},
		{schema.Integer, 4.0, int64(4)},
		{schema.Integer, uint8(4), int64(4)},
		{schema.Boolean, true, true},
		{schema.Date, time.Date(2020, 1, 1, 1, 0, 0, 123456789, time.FixedZone("x", 3600)), time.Date(2020, 1, 1, 0, 0, 0, 123000000, time.UTC)},
		{schema.StringArray, []string{"a"}, []string{"a"}},
		{schema.NumberArray, []int{1, 2}, []float64{1, 2}},
		{schema.JSON, map[string]any{"a": 1}, json.RawMessage(`{"a":1}`)},
		{schema.JSON, "text", json.RawMessage(`"text"`)},
		{schema.ID, "abc", "abc"},
	}
	for _, c := range cases {
		got, err := schema.Normalize(c.t, c.in)
		require.NoError(t, err, "%s %v", c.t, c.in)
		require.Equal(t, c.want, got, "%s %v", c.t, c.in)
	}
	for _, bad := range []struct {
		t  schema.FieldType
		in any
	}{{schema.Boolean, 1}, {schema.Number, "1"}, {schema.JSON, json.RawMessage("{")}, {schema.Date, 5}, {"nope", 1}} {
		_, err := schema.Normalize(bad.t, bad.in)
		require.Error(t, err, "%s %v", bad.t, bad.in)
	}
}
