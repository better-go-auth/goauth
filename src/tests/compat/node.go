package compattest

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// ClientDir returns the absolute path of a Node client directory under src/tests/compat
// (e.g. "client" for the shared better-auth client, "client-passkey" for @better-auth/passkey).
func ClientDir(name string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), name)
}

// RunNodeClient runs `node <script>` inside the client directory dir with GOAUTH_URL=baseURL plus env,
// failing the test with the script output when it exits non-zero. It skips when node or the
// directory's node_modules are missing.
func RunNodeClient(t *testing.T, dir, script, baseURL string, env ...string) string {
	t.Helper()
	// Step 1: skip cleanly on machines without node or without the installed client packages
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed, skipping official better-auth client test")
	}
	if _, err := os.Stat(filepath.Join(dir, "node_modules")); err != nil {
		t.Skipf("%s/node_modules missing (run npm install there), skipping client test", dir)
	}
	if _, err := os.Stat(filepath.Join(dir, script)); err != nil {
		t.Fatalf("client script not found: %v", err)
	}
	// Step 2: run the script against the in-process server
	cmd := exec.Command("node", script)
	cmd.Dir = dir
	cmd.Env = append(append(os.Environ(), "GOAUTH_URL="+baseURL), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("official better-auth client script %s failed: %v\nOutput:\n%s", script, err, string(out))
	}
	t.Logf("%s output:\n%s", script, string(out))
	return string(out)
}
