package compat

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// tsCodesPath points at the better-auth checkout that sits next to goauth in this workspace.
var tsCodesPath = filepath.Join("..", "..", "better-auth", "packages", "core", "src", "error", "codes.ts")

func loadSnapshot(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "base_error_codes.json"))
	if err != nil {
		t.Fatal(err)
	}
	var codes map[string]string
	if err := json.Unmarshal(raw, &codes); err != nil {
		t.Fatal(err)
	}
	return codes
}

func TestBaseErrorCodesMatchBetterAuth(t *testing.T) {
	for code, msg := range loadSnapshot(t) {
		e, ok := Lookup(code)
		if !ok {
			t.Errorf("missing code %s", code)
			continue
		}
		if e.Message != msg {
			t.Errorf("%s: message %q, want %q", code, e.Message, msg)
		}
		if e.Status < 400 || e.Status > 599 {
			t.Errorf("%s: invalid status %d", code, e.Status)
		}
	}
}

// TestSnapshotInSyncWithTypeScript fails when better-auth adds or changes a base code.
func TestSnapshotInSyncWithTypeScript(t *testing.T) {
	src, err := os.ReadFile(tsCodesPath)
	if err != nil {
		t.Skipf("better-auth source not available: %v", err)
	}
	re := regexp.MustCompile(`(?m)^\s*([A-Z][A-Z_]+):\s*"((?:[^"\\]|\\.)*)"`)
	ts := map[string]string{}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		ts[m[1]] = m[2]
	}
	if len(ts) == 0 {
		t.Fatal("no codes parsed from codes.ts")
	}
	snap := loadSnapshot(t)
	for code, msg := range ts {
		if snap[code] != msg {
			t.Errorf("%s: snapshot %q, codes.ts %q", code, snap[code], msg)
		}
	}
	for code := range snap {
		if _, ok := ts[code]; !ok {
			t.Errorf("%s: in snapshot but removed from codes.ts", code)
		}
	}
}

func TestAPIErrorBehaviour(t *testing.T) {
	e := ErrInvalidToken.WithStatus(http.StatusUnauthorized)
	if e.Status != http.StatusUnauthorized || ErrInvalidToken.Status != http.StatusBadRequest {
		t.Fatal("WithStatus must copy, not mutate")
	}
	if !errors.Is(e, ErrInvalidToken) {
		t.Fatal("copies must match the original code via errors.Is")
	}
	body, _ := json.Marshal(e)
	if string(body) != `{"code":"INVALID_TOKEN","message":"Invalid token"}` {
		t.Fatalf("unexpected body %s", body)
	}
}

func TestRegister(t *testing.T) {
	e := Register("TEST_PLUGIN_CODE", "Test plugin code")
	if got, ok := Lookup("TEST_PLUGIN_CODE"); !ok || got != e || got.Status != http.StatusBadRequest {
		t.Fatalf("Register/Lookup mismatch: %+v", got)
	}
	if Register("TEST_PLUGIN_CODE", "Test plugin code") != e {
		t.Fatal("re-registering the same code and message must be idempotent")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("conflicting message must panic")
		}
	}()
	Register("TEST_PLUGIN_CODE", "different")
}
