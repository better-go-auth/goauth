package schema_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNoStorageDependencies enforces doc 04 §4.1: the registry is storage-neutral, so the package (not its
// tests) must never depend on GORM, a database driver, database/sql or goauth's config/models packages.
func TestNoStorageDependencies(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, out)
	}
	forbidden := []string{
		"gorm.io/",
		"database/sql",
		"github.com/mattn/go-sqlite3",
		"github.com/jackc/",
		"github.com/go-sql-driver/",
		"github.com/lib/pq",
		"go.mongodb.org/",
		"github.com/uptrace/bun",
		"github.com/better-go-auth/goauth/src/config",
		"github.com/better-go-auth/goauth/src/models",
		"github.com/better-go-auth/goauth/src/adapter",
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, f := range forbidden {
			if strings.HasPrefix(dep, f) {
				t.Errorf("src/schema depends on %s (forbidden prefix %s)", dep, f)
			}
		}
	}
}
