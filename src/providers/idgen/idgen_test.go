package idgen

import (
	"regexp"
	"testing"
)

func TestRandomIDs(t *testing.T) {
	re := regexp.MustCompile(`^[a-zA-Z0-9]{32}$`)
	seen := map[string]bool{}
	for range 100 {
		id := GenerateID()
		if !re.MatchString(id) || seen[id] {
			t.Fatalf("bad or duplicate id %q", id)
		}
		seen[id] = true
	}
	if len(ULID()) != 26 {
		t.Fatal("ULID must be 26 chars")
	}
}
