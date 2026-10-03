package compattest

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update-golden", false, "rewrite golden files from the current responses")

// GoldenDir is src/tests/compat/golden, resolved from this source file.
var GoldenDir = func() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "golden")
}()

// AssertJSONShape compares got with golden/<name>.json.
//
// Golden string values of the form "<type>" are placeholders: <string>, <number>, <bool>,
// <date> (RFC 3339), <null>, <any>, and unions such as "<string|null>". Everything else must
// match exactly, and objects must have exactly the same keys.
func AssertJSONShape(t testing.TB, got []byte, name string) {
	t.Helper()
	path := filepath.Join(GoldenDir, name+".json")

	var gotV any
	if err := json.Unmarshal(got, &gotV); err != nil {
		t.Fatalf("compattest: response is not JSON: %v\n%s", err, got)
	}

	if *update {
		out, _ := json.MarshalIndent(Shape(gotV), "", "  ")
		if err := os.MkdirAll(GoldenDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("compattest: read golden %s: %v (run with -update-golden to create it)", path, err)
	}
	var want any
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("compattest: golden %s is not JSON: %v", path, err)
	}
	if diffs := MatchShape(want, gotV, "$"); len(diffs) > 0 {
		var pretty bytes.Buffer
		_ = json.Indent(&pretty, got, "", "  ")
		t.Fatalf("compattest: %s does not match golden:\n  %s\ngot:\n%s", name, strings.Join(diffs, "\n  "), pretty.String())
	}
}

// MatchShape returns the differences between a golden value and an actual value.
func MatchShape(want, got any, path string) []string {
	if s, ok := want.(string); ok && isPlaceholder(s) {
		for _, alt := range strings.Split(s[1:len(s)-1], "|") {
			if matchesType(alt, got) {
				return nil
			}
		}
		return []string{fmt.Sprintf("%s: want %s, got %s", path, s, describe(got))}
	}

	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return []string{fmt.Sprintf("%s: want object, got %s", path, describe(got))}
		}
		var diffs []string
		for _, k := range sortedKeys(w) {
			gv, ok := g[k]
			if !ok {
				diffs = append(diffs, fmt.Sprintf("%s.%s: missing", path, k))
				continue
			}
			diffs = append(diffs, MatchShape(w[k], gv, path+"."+k)...)
		}
		for _, k := range sortedKeys(g) {
			if _, ok := w[k]; !ok {
				diffs = append(diffs, fmt.Sprintf("%s.%s: unexpected key", path, k))
			}
		}
		return diffs
	case []any:
		g, ok := got.([]any)
		if !ok {
			return []string{fmt.Sprintf("%s: want array, got %s", path, describe(got))}
		}
		if len(w) != len(g) {
			return []string{fmt.Sprintf("%s: want %d elements, got %d", path, len(w), len(g))}
		}
		var diffs []string
		for i := range w {
			diffs = append(diffs, MatchShape(w[i], g[i], fmt.Sprintf("%s[%d]", path, i))...)
		}
		return diffs
	default:
		if fmt.Sprint(want) != fmt.Sprint(got) || describe(want) != describe(got) {
			return []string{fmt.Sprintf("%s: want %v, got %v", path, want, got)}
		}
		return nil
	}
}

// Shape replaces volatile values with placeholders; booleans and nulls are kept literally.
func Shape(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = Shape(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = Shape(val)
		}
		return out
	case string:
		if isDate(x) {
			return "<date>"
		}
		return "<string>"
	case float64:
		return "<number>"
	default:
		return x
	}
}

func isPlaceholder(s string) bool {
	return len(s) > 2 && s[0] == '<' && s[len(s)-1] == '>'
}

func matchesType(typ string, v any) bool {
	switch typ {
	case "any":
		return true
	case "null":
		return v == nil
	case "string":
		_, ok := v.(string)
		return ok
	case "date":
		s, ok := v.(string)
		return ok && isDate(s)
	case "number":
		_, ok := v.(float64)
		return ok
	case "bool":
		_, ok := v.(bool)
		return ok
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	}
	return false
}

func isDate(s string) bool {
	_, err := time.Parse(time.RFC3339Nano, s)
	return err == nil
}

func describe(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "bool"
	case map[string]any:
		return "object"
	case []any:
		return "array"
	}
	return fmt.Sprintf("%T", v)
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
