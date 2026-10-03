package hasher

import "testing"

func TestTokenHashRoundTrip(t *testing.T) {
	h := TokenHash("refresh-token")
	if len(h) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(h))
	}
	if !TokenMatches("refresh-token", h) {
		t.Fatal("expected token to match its hash")
	}
	if TokenMatches("other-token", h) {
		t.Fatal("expected different token not to match")
	}
}

func TestTokenMatchesLegacyArgon(t *testing.T) {
	legacy, err := ArgonCreateHash("refresh-token")
	if err != nil {
		t.Fatal(err)
	}
	if !TokenMatches("refresh-token", legacy) {
		t.Fatal("expected legacy argon2 hash to match")
	}
	if TokenMatches("other-token", legacy) {
		t.Fatal("expected different token not to match legacy hash")
	}
}
