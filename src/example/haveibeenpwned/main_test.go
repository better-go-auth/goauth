package main

import (
	"crypto/sha1" //nolint:gosec // the range API is keyed by SHA-1
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
)

// fakeRangeAPI knows one breached password ("password123") and answers GET /range/<prefix> like the real API.
func fakeRangeAPI(t *testing.T) *httptest.Server {
	t.Helper()
	sum := sha1.Sum([]byte("password123")) //nolint:gosec // test corpus
	breached := strings.ToUpper(hex.EncodeToString(sum[:]))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := strings.TrimPrefix(r.URL.Path, "/range/")
		if prefix == breached[:5] {
			_, _ = fmt.Fprintf(w, "%s:123456\r\n", breached[5:])
		}
		_, _ = fmt.Fprint(w, "0000000000000000000000000000000000A:0")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestHaveIBeenPwnedFlow(t *testing.T) {
	app, err := newApp("", fakeRangeAPI(t).URL+"/range/")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)

	// Step 1: a breached password is refused with the custom message
	r := c.SignUp("alice@example.com", "password123", "Alice")
	if r.Status != http.StatusBadRequest || r.ErrorCode() != "PASSWORD_COMPROMISED" {
		t.Fatalf("breached password: %d %s", r.Status, r.Body)
	}
	if !strings.Contains(string(r.Body), "data breach") {
		t.Fatalf("message = %s", r.Body)
	}
	// Step 2: a unique password works
	c.MustOK(c.SignUp("alice@example.com", "Correct-Horse-42!", "Alice"), nil)
	// Step 3: changing to a breached password is refused too
	r = c.Post("/api/auth/change-password", map[string]any{"currentPassword": "Correct-Horse-42!", "newPassword": "password123"})
	if r.Status != http.StatusBadRequest || r.ErrorCode() != "PASSWORD_COMPROMISED" {
		t.Fatalf("change-password: %d %s", r.Status, r.Body)
	}
	// Step 4: sign-in is never checked
	c.Fork().MustOK(c.Fork().SignIn("alice@example.com", "Correct-Horse-42!"), nil)
}
