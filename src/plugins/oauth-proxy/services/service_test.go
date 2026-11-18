package services

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/config"
	proxyconfig "github.com/better-go-auth/goauth/src/plugins/oauth-proxy/config"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

func TestEncodeURIComponent(t *testing.T) {
	cases := map[string]string{
		"/dashboard":                    "%2Fdashboard",
		"https://a.b/c?d=e&f=g h":       "https%3A%2F%2Fa.b%2Fc%3Fd%3De%26f%3Dg%20h",
		"-_.!~*'()":                     "-_.!~*'()",
		"é":                             "%C3%A9",
		"http://localhost:3000/x#frag+": "http%3A%2F%2Flocalhost%3A3000%2Fx%23frag%2B",
	}
	for in, want := range cases {
		if got := encodeURIComponent(in); got != want {
			t.Errorf("encodeURIComponent(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSetSearchParam(t *testing.T) {
	cases := []struct{ raw, key, value, want string }{
		{"https://p/a?z=1&state=old&a=2", "state", "new", "https://p/a?z=1&state=new&a=2"},
		{"https://p/a?callbackURL=%2Fx", "profile", "abc", "https://p/a?callbackURL=%2Fx&profile=abc"},
		{"https://p/a?state=1&state=2&b=3", "state", "x y", "https://p/a?state=x+y&b=3"},
		{"https://p/a", "k", "v", "https://p/a?k=v"},
	}
	for _, tc := range cases {
		u, _ := url.Parse(tc.raw)
		setSearchParam(u, tc.key, tc.value)
		if u.String() != tc.want {
			t.Errorf("set %s on %s = %s, want %s", tc.key, tc.raw, u.String(), tc.want)
		}
	}
}

func TestOriginOf(t *testing.T) {
	cases := map[string]string{
		"https://Example.com/api/auth": "https://example.com",
		"http://localhost:80/x":        "http://localhost",
		"https://a.com:443":            "https://a.com",
		"http://127.0.0.1:3000/a?b":    "http://127.0.0.1:3000",
		"http://[::1]:8080/":           "http://[::1]:8080",
		"/relative":                    "",
		"not a url":                    "",
	}
	for in, want := range cases {
		if got := originOf(in); got != want {
			t.Errorf("originOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReplaceJSONField(t *testing.T) {
	out, ok := replaceJSONField([]byte(`{"url":"https://a?b=1&c=2","redirect":true}`+"\n"), "url", "https://x?y=<1>&z")
	if !ok || string(out) != `{"url":"https://x?y=<1>&z","redirect":true}` {
		t.Fatalf("got %s %v", out, ok)
	}
	out, ok = replaceJSONField([]byte(`{"redirect":false}`), "url", "u")
	if !ok || string(out) != `{"redirect":false,"url":"u"}` {
		t.Fatalf("append: %s", out)
	}
	if _, ok := replaceJSONField([]byte(`[1]`), "url", "u"); ok {
		t.Fatal("arrays are not objects")
	}
}

// newTestService builds a service over a minimal kit (no repositories needed for the URL logic).
func newTestService(cfg proxyconfig.OAuthProxyConfig, conf config.AuthConfig) *Service {
	kit := &pluginkit.Kit{Conf: conf, BasePath: "/api/auth"}
	return New(kit, cfg, nil)
}

// hookCtx is a hook context for a request to target with headers.
func hookCtx(target string, headers map[string]string) *endpointhooks.Context {
	u, _ := url.Parse(target)
	r := &http.Request{Method: http.MethodPost, URL: &url.URL{Path: u.Path, RawQuery: u.RawQuery}, Host: u.Host, Header: http.Header{}}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return endpointhooks.NewContext(context.Background(), "/sign-in/social", http.MethodPost, r, nil)
}

func TestRequestURLAndSkip(t *testing.T) {
	t.Setenv("BETTER_AUTH_URL", "")
	t.Setenv("VERCEL_URL", "")
	conf := config.AuthConfig{BaseURL: "https://prod.example.com"}
	// Step 1: the scheme comes from X-Forwarded-Proto, then BaseURL for the same host, then http
	s := newTestService(proxyconfig.OAuthProxyConfig{ProductionURL: "https://prod.example.com"}, conf)
	if got := s.requestURL(hookCtx("http://prod.example.com/api/auth/sign-in/social", nil).Request); got != "https://prod.example.com/api/auth/sign-in/social" {
		t.Fatalf("same host: %s", got)
	}
	if got := s.requestURL(hookCtx("http://preview.example.com/a?b=1", nil).Request); got != "http://preview.example.com/a?b=1" {
		t.Fatalf("other host: %s", got)
	}
	if got := s.requestURL(hookCtx("http://preview.example.com/a", map[string]string{"X-Forwarded-Proto": "https, http"}).Request); got != "https://preview.example.com/a" {
		t.Fatalf("forwarded: %s", got)
	}
	// Step 2: checkSkipProxy: header, same origin, different origin
	if !s.checkSkipProxy(hookCtx("http://preview.example.com/a", map[string]string{SkipProxyHeader: "true"})) {
		t.Fatal("header must skip")
	}
	if !s.checkSkipProxy(hookCtx("http://prod.example.com/a", nil)) {
		t.Fatal("production must skip")
	}
	if s.checkSkipProxy(hookCtx("http://preview.example.com/a", nil)) {
		t.Fatal("preview must proxy")
	}
	// Step 3: CurrentURL wins over the request
	s2 := newTestService(proxyconfig.OAuthProxyConfig{ProductionURL: "https://prod.example.com", CurrentURL: "https://prod.example.com"}, conf)
	if !s2.checkSkipProxy(hookCtx("http://preview.example.com/a", nil)) {
		t.Fatal("CurrentURL = production must skip")
	}
	// Step 4: without ProductionURL, $BETTER_AUTH_URL, then the base URL
	s3 := newTestService(proxyconfig.OAuthProxyConfig{}, conf)
	if s3.checkSkipProxy(hookCtx("http://preview.example.com/a", nil)) {
		t.Fatal("base URL production, preview request must proxy")
	}
	t.Setenv("BETTER_AUTH_URL", "http://preview.example.com")
	if !s3.checkSkipProxy(hookCtx("http://preview.example.com/a", nil)) {
		t.Fatal("BETTER_AUTH_URL = current origin must skip")
	}
}

func TestResolveCurrentURL(t *testing.T) {
	t.Setenv("VERCEL_URL", "my-app-git-x.vercel.app")
	s := newTestService(proxyconfig.OAuthProxyConfig{}, config.AuthConfig{BaseURL: "https://prod.example.com"})
	// the request URL comes first
	u, err := s.resolveCurrentURL(hookCtx("http://preview.example.com/a", nil))
	if err != nil || u.Host != "preview.example.com" {
		t.Fatalf("request: %v %v", u, err)
	}
	// without a request: the vendor URL
	c := endpointhooks.NewContext(context.Background(), "/sign-in/social", http.MethodPost, nil, nil)
	u, err = s.resolveCurrentURL(c)
	if err != nil || u.String() != "https://my-app-git-x.vercel.app" {
		t.Fatalf("vendor: %v %v", u, err)
	}
	// then the base URL
	t.Setenv("VERCEL_URL", "")
	u, err = s.resolveCurrentURL(c)
	if err != nil || u.String() != "https://prod.example.com/api/auth" {
		t.Fatalf("base: %v %v", u, err)
	}
	// a relative CurrentURL is invalid (new URL throws)
	s.cfg.CurrentURL = "/relative"
	if _, err := s.resolveCurrentURL(c); err == nil {
		t.Fatal("relative CurrentURL must fail")
	}
}

func TestDefaults(t *testing.T) {
	s := newTestService(proxyconfig.OAuthProxyConfig{}, config.AuthConfig{Secret: "core"})
	if s.Config().MaxAge != proxyconfig.DefaultMaxAge || s.key() != "core" {
		t.Fatalf("defaults: %+v key=%s", s.Config(), s.key())
	}
	s = newTestService(proxyconfig.OAuthProxyConfig{Secret: "proxy"}, config.AuthConfig{Secret: "core"})
	if s.key() != "proxy" {
		t.Fatal("secret option")
	}
	if got := s.defaultErrorURL(context.Background()); got != "/api/auth/error" {
		t.Fatalf("no base URL: %s", got)
	}
	s = newTestService(proxyconfig.OAuthProxyConfig{}, config.AuthConfig{BaseURL: "https://app.example.com/"})
	if got := s.defaultErrorURL(context.Background()); got != "https://app.example.com/api/auth/error" {
		t.Fatalf("error URL: %s", got)
	}
}
