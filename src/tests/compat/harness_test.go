package compattest

import (
	"context"
	"net/http"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/danielgtaylor/huma/v2"
)

func TestAssertJSONShapeAcceptsBetterAuthLikeBody(t *testing.T) {
	body := []byte(`{
		"redirect": false,
		"token": "abc",
		"url": null,
		"user": {"id": "u1", "name": "A", "email": "a@x.io", "emailVerified": false, "image": null,
			"createdAt": "2026-01-01T00:00:00.000Z", "updatedAt": "2026-01-01T00:00:00.000Z"}
	}`)
	AssertJSONShape(t, body, "harness_selftest")
}

func TestMatchShape(t *testing.T) {
	cases := []struct {
		name      string
		want, got any
		ok        bool
	}{
		{"literal equal", true, true, true},
		{"literal differs", true, false, false},
		{"string placeholder", "<string>", "x", true},
		{"string placeholder wrong type", "<string>", 1.0, false},
		{"union null", "<string|null>", nil, true},
		{"date", "<date>", "2026-01-01T00:00:00.000Z", true},
		{"bad date", "<date>", "yesterday", false},
		{"missing key", map[string]any{"a": "<any>"}, map[string]any{}, false},
		{"extra key", map[string]any{}, map[string]any{"a": 1.0}, false},
		{"array length", []any{"<string>"}, []any{"a", "b"}, false},
		{"number vs string literal", "1", 1.0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			diffs := MatchShape(tc.want, tc.got, "$")
			if (len(diffs) == 0) != tc.ok {
				t.Fatalf("ok=%v, diffs=%v", tc.ok, diffs)
			}
		})
	}
}

func TestServerRoundTripsCookies(t *testing.T) {
	s := NewServer(t, WithConfig(func(c *config.AuthConfig) { c.AppName = "compat-harness" }))

	type setOut struct {
		SetCookie http.Cookie `header:"Set-Cookie"`
	}
	type echoIn struct {
		Cookie string `header:"Cookie"`
	}
	type echoOut struct {
		Body struct {
			Cookie string `json:"cookie"`
		}
	}
	huma.Register(s.API, huma.Operation{Method: http.MethodPost, Path: "/test/set-cookie"},
		func(ctx context.Context, _ *struct{}) (*setOut, error) {
			return &setOut{SetCookie: http.Cookie{Name: "better-auth.session_token", Value: "tok", Path: "/"}}, nil
		})
	huma.Register(s.API, huma.Operation{Method: http.MethodGet, Path: "/test/echo-cookie"},
		func(ctx context.Context, in *echoIn) (*echoOut, error) {
			out := &echoOut{}
			out.Body.Cookie = in.Cookie
			return out, nil
		})

	set := s.Post(t, "/test/set-cookie", nil)
	if c := set.Cookie("better-auth.session_token"); c == nil || c.Value != "tok" {
		t.Fatalf("expected session cookie on response, got %v", set.Header)
	}
	var echo struct{ Cookie string }
	s.Get(t, "/test/echo-cookie").JSON(t, &echo)
	if echo.Cookie != "better-auth.session_token=tok" {
		t.Fatalf("cookie jar did not resend cookie: %q", echo.Cookie)
	}
	if s.Auth.Options.AppName != "compat-harness" {
		t.Fatalf("options not applied: %q", s.Auth.Options.AppName)
	}
	if r := s.Get(t, "/api/auth/does-not-exist"); r.Status != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", r.Status)
	}
}
