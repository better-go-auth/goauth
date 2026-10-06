package authcrypto

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
