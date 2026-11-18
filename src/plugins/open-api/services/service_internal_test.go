package services

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/schema"
)

func TestEncodeURIComponent(t *testing.T) {
	// expected values are JavaScript's encodeURIComponent output
	cases := map[string]string{
		"abcXYZ019-_.!~*'()":         "abcXYZ019-_.!~*'()",
		"a b<>/?:@&=+$#":             "a%20b%3C%3E%2F%3F%3A%40%26%3D%2B%24%23",
		"é€😀":                        "%C3%A9%E2%82%AC%F0%9F%98%80",
		"<svg width=\"75\">\n</svg>": "%3Csvg%20width%3D%2275%22%3E%0A%3C%2Fsvg%3E",
	}
	for in, want := range cases {
		if got := EncodeURIComponent(in); got != want {
			t.Errorf("EncodeURIComponent(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOperationIDs(t *testing.T) {
	// better-auth's uniqueOperationId: first as is, then + PascalCase method, then a counter
	ids := newOperationIDs()
	got := []string{ids.unique("x", "get"), ids.unique("x", "post"), ids.unique("x", "post"), ids.unique("y", "get")}
	want := []string{"x", "xPost", "xPost2", "y"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ids = %v, want %v", got, want)
		}
	}
}

func TestRefResolver(t *testing.T) {
	// Step 1: refs are inlined, recursion is cut, $schema properties are dropped
	r := &refResolver{schemas: map[string]any{
		"Node": map[string]any{"type": "object", "properties": map[string]any{
			"$schema": map[string]any{"type": "string"},
			"next":    map[string]any{"$ref": "#/components/schemas/Node"},
			"leaf":    map[string]any{"$ref": "#/components/schemas/Leaf"},
		}},
		"Leaf": map[string]any{"type": "string"},
	}}
	out := r.resolve(map[string]any{"$ref": "#/components/schemas/Node"})
	b, _ := json.Marshal(out)
	s := string(b)
	if strings.Contains(s, "$ref") || strings.Contains(s, "$schema") {
		t.Fatalf("resolved = %s", s)
	}
	if s != `{"properties":{"leaf":{"type":"string"},"next":{"type":"object"}},"type":"object"}` {
		t.Fatalf("resolved = %s", s)
	}
	// Step 2: an unknown ref becomes an object, other values are copied
	if b, _ := json.Marshal(r.resolve([]any{map[string]any{"$ref": "#/components/schemas/Missing"}, 1.0})); string(b) != `[{"type":"object"},1]` {
		t.Fatalf("unknown = %s", b)
	}
}

func TestFieldSchema(t *testing.T) {
	now := func() any { return nil }
	cases := []struct {
		f    schema.Field
		want string
	}{
		{schema.Field{Type: schema.String}, `{"type":"string"}`},
		{schema.Field{Type: schema.Date, Default: now}, `{"default":"Generated at runtime","format":"date-time","type":"string"}`},
		{schema.Field{Type: schema.Boolean, Default: false, Input: schema.Bool(false)}, `{"default":false,"readOnly":true,"type":"boolean"}`},
		{schema.Field{Type: schema.Integer}, `{"type":"number"}`},
		{schema.Field{Type: schema.NumberArray}, `{"items":{"type":"number"},"type":"array"}`},
		{schema.Field{Type: schema.String, Enum: []string{"a", "b"}, Default: "a"}, `{"default":"a","enum":["a","b"],"type":"string"}`},
	}
	for _, c := range cases {
		b, _ := json.Marshal(fieldSchema(c.f))
		if string(b) != c.want {
			t.Errorf("fieldSchema(%+v) = %s, want %s", c.f.Type, b, c.want)
		}
	}
}

func TestReferenceHTML(t *testing.T) {
	page, err := ReferenceHTML(map[string]any{"a": "</script>"}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	// the default theme, no nonce attribute, and a description cannot close the script element
	if !strings.Contains(page, `theme: "default"`) || strings.Contains(page, "nonce=") || strings.Count(page, "</script>") != 3 {
		t.Fatalf("page = %s", page[:200])
	}
}
