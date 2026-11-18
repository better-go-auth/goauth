package render_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// runInTempModule writes files into a fresh Go module that requires reqs (module path → version) and runs
// each `go <args...>` command in it, in order, offline (GOPROXY=off: only the module cache; set
// GOAUTH_TEST_GOPROXY, and GOMODCACHE to a scratch directory, to allow downloads). It skips the test when
// the modules are not in the cache and fails on any other error (a compile error of generated code).
func runInTempModule(t *testing.T, reqs map[string]string, files map[string]string, commands ...[]string) {
	t.Helper()
	runCommands(t, reqs, files, commands)
}

// runInTempModuleOutput is runInTempModule for one command; it returns the command's standard output.
func runInTempModuleOutput(t *testing.T, reqs map[string]string, files map[string]string, args ...string) string {
	t.Helper()
	return runCommands(t, reqs, files, [][]string{args})
}

// runCommands implements runInTempModule and returns the standard output of the last command.
func runCommands(t *testing.T, reqs map[string]string, files map[string]string, commands [][]string) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go is not in PATH")
	}
	dir := t.TempDir()
	// Step 1: go.mod and the sources
	var mod strings.Builder
	mod.WriteString("module goauthgen\n\ngo 1.23\n\nrequire (\n")
	for path, version := range reqs {
		mod.WriteString("\t" + path + " " + version + "\n")
	}
	mod.WriteString(")\n")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod.String()), 0o644))
	for name, src := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
	}
	proxy := os.Getenv("GOAUTH_TEST_GOPROXY")
	if proxy == "" {
		proxy = "off"
	}
	var last string
	for _, args := range commands {
		// Step 2: run offline
		cmd := exec.Command(goBin, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOPROXY="+proxy, "GOSUMDB=off", "GOWORK=off", "GOTOOLCHAIN=local")
		var stderr strings.Builder
		cmd.Stderr = &stderr
		stdout, err := cmd.Output()
		last = string(stdout)
		if err == nil {
			continue
		}
		// Step 3: modules missing from the cache are an environment problem, not a test failure
		out := last + stderr.String()
		for _, missing := range []string{"module lookup disabled", "cannot find module", "GOPROXY=off", "missing go.sum entry", "no required module provides"} {
			if strings.Contains(out, missing) {
				t.Skipf("modules %v are not in the module cache: %s", reqs, firstLine(out))
			}
		}
		require.NoError(t, err, "go %s:\n%s", strings.Join(args, " "), out)
	}
	return last
}

// firstLine returns the first line of s.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
