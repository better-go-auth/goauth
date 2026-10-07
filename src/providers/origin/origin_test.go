package origin

import (
	"testing"

	"github.com/better-go-auth/goauth/src/config"
)

func TestChecker(t *testing.T) {
	c := New(config.AuthConfig{
		BaseURL:        "https://app.example.com/base",
		TrustedOrigins: []string{"https://admin.example.com", "*.preview.example.com", "https://*.cdn.example.com", "myapp://"},
	})
	cases := []struct {
		url      string
		relative bool
		want     bool
	}{
		{"https://app.example.com", false, true},
		{"https://app.example.com/some/page?x=1", false, true},
		{"http://app.example.com", false, false},
		{"https://admin.example.com", false, true},
		{"https://evil.com", false, false},
		{"https://app.example.com.evil.com", false, false},
		{"https://pr-1.preview.example.com", false, true},
		{"https://img.cdn.example.com/a.png", false, true},
		{"http://img.cdn.example.com", false, false},
		{"myapp://callback", false, true},
		{"/dashboard", true, true},
		{"/dashboard?tab=1", true, true},
		{"/dashboard", false, false},
		{"//evil.com", true, false},
		{`/\evil.com`, true, false},
		{"/%2fevil.com", true, false},
	}
	for _, tc := range cases {
		if got := c.IsTrusted(tc.url, tc.relative); got != tc.want {
			t.Errorf("IsTrusted(%q, %v) = %v, want %v", tc.url, tc.relative, got, tc.want)
		}
	}
}
