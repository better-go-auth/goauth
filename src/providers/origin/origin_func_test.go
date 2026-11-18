package origin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
)

func TestTrustedOriginsFuncAndDynamicBaseURL(t *testing.T) {
	// Step 1: the function sees each request; nil outside a request
	var sawNil bool
	c := New(config.AuthConfig{
		BaseURL: "https://app.example.com",
		TrustedOriginsFunc: func(r *http.Request) []string {
			if r == nil {
				sawNil = true
				return nil
			}
			return []string{r.Header.Get("X-Tenant-Origin"), ""}
		},
	})
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("X-Tenant-Origin", "https://tenant-a.example.org")
	if !c.IsTrustedFor(r, "https://tenant-a.example.org/cb", false) {
		t.Fatal("origin from the request function must be trusted")
	}
	if c.IsTrustedFor(r, "https://tenant-b.example.org", false) {
		t.Fatal("other origins must not be trusted")
	}
	if c.IsTrusted("https://tenant-a.example.org", false) || !sawNil {
		t.Fatal("without a request the function gets nil")
	}
	if !c.IsTrustedFor(r, "https://app.example.com/x", false) {
		t.Fatal("the base URL stays trusted")
	}
	// Step 2: a dynamic base URL trusts its allowed hosts (+ fallback) instead of a static BaseURL
	d := New(config.AuthConfig{DynamicBaseURL: &config.DynamicBaseURL{AllowedHosts: []string{"*.vercel.app", "localhost:3000"}, Fallback: "https://main.example"}})
	for raw, want := range map[string]bool{
		"https://pr-1.vercel.app":  true,
		"http://pr-1.vercel.app":   false,
		"http://localhost:3000/cb": true,
		"https://main.example/x":   true,
		"https://evil.example":     false,
	} {
		if got := d.IsTrusted(raw, false); got != want {
			t.Fatalf("%s: got %v want %v", raw, got, want)
		}
	}
}
