// Package configparity tests better-auth's core config behaviour on a real goauth server: the global rate
// limiter (rateLimit), endpoint hooks (hooks.before/after and plugin hooks), onAPIError, the logger option
// and advanced.backgroundTasks.
package configparity

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/providers/ratelimit"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

const password = "Password123!"

// prodSecret is a non-development secret, so servers can run with GOAUTH_ENV=production.
const prodSecret = "a-production-grade-secret-0123456789abcdef"

// signUp creates a user with email + password and returns the response.
func signUp(t *testing.T, s *compattest.Server, email string) *compattest.Response {
	t.Helper()
	res := s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": email, "password": password, "name": "Test User"})
	if res.Status != http.StatusOK {
		t.Fatalf("sign-up %s: %d %s", email, res.Status, res.Body)
	}
	return res
}

// signIn signs in with email + password from ip (X-Forwarded-For).
func signIn(t *testing.T, s *compattest.Server, email, pass, ip string) *compattest.Response {
	t.Helper()
	return s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": email, "password": pass},
		map[string]string{"X-Forwarded-For": ip})
}

// enabled returns a config option turning the rate limiter on.
func enabled(fn ...func(*config.AuthConfig)) compattest.Option {
	return compattest.WithConfig(func(c *config.AuthConfig) {
		c.RateLimit.Enabled = new(true)
		for _, f := range fn {
			f(c)
		}
	})
}

// expect429 checks better-auth's exact rate-limit response.
func expect429(t *testing.T, res *compattest.Response, maxRetry int) {
	t.Helper()
	if res.Status != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d %s", res.Status, res.Body)
	}
	if got := string(res.Body); got != `{"message":"Too many requests. Please try again later."}` {
		t.Fatalf("429 body = %q", got)
	}
	if ct := res.Header.Get("Content-Type"); ct != "text/plain;charset=UTF-8" {
		t.Fatalf("429 content type = %q", ct)
	}
	retry := res.Header.Get("X-Retry-After")
	n := 0
	for _, ch := range retry {
		n = n*10 + int(ch-'0')
	}
	if retry == "" || strings.Trim(retry, "0123456789") != "" || n < 1 || n > maxRetry {
		t.Fatalf("X-Retry-After = %q (max %d)", retry, maxRetry)
	}
}

// ─── test plugin ─────────────────────────────────────────────────────────────

// recorder collects hook calls in order (safe for concurrent use).
type recorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *recorder) add(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, s)
}

func (r *recorder) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func (r *recorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = nil
}

// testPlugin mounts GET /test-plugin/ping and /test-plugin/limited and can declare rate-limit rules and
// endpoint hooks, like a third-party better-auth plugin.
type testPlugin struct {
	id    string
	rules []ratelimit.PathRule
	hooks endpointhooks.Hooks
	// routeRule is set on /test-plugin/limited through pluginkit.Route.RateLimit
	routeRule *ratelimit.Rule
	pings     int
	mu        sync.Mutex
}

var (
	_ plugins.Plugin                = (*testPlugin)(nil)
	_ plugins.RateLimitProvider     = (*testPlugin)(nil)
	_ plugins.EndpointHooksProvider = (*testPlugin)(nil)
)

type pingOutput struct {
	Body struct {
		Pong bool `json:"pong"`
	}
}

func (p *testPlugin) ID() string                           { return p.id }
func (p *testPlugin) Migrator() migration.IMigrator        { return nil }
func (p *testPlugin) Services() map[string]any             { return nil }
func (p *testPlugin) Routes() []plugins.RouteDescriptor    { return nil }
func (p *testPlugin) RateLimitRules() []ratelimit.PathRule { return p.rules }
func (p *testPlugin) EndpointHooks() endpointhooks.Hooks   { return p.hooks }
func (p *testPlugin) pingCount() int                       { p.mu.Lock(); defer p.mu.Unlock(); return p.pings }
func (p *testPlugin) ping(context.Context, *struct{}) (*pingOutput, error) {
	p.mu.Lock()
	p.pings++
	p.mu.Unlock()
	out := &pingOutput{}
	out.Body.Pong = true
	return out, nil
}

func (p *testPlugin) Init(ictx *plugins.InitContext) error {
	// only the first test plugin mounts the routes (several instances can declare hooks)
	if p.id != "test-plugin" {
		return nil
	}
	kit, err := pluginkit.New(ictx)
	if err != nil {
		return err
	}
	pluginkit.Register(kit, ictx.Api, pluginkit.Route{
		OperationID: "testPluginPing", Method: http.MethodGet, Path: "/test-plugin/ping", Access: pluginkit.Public,
	}, p.ping)
	pluginkit.Register(kit, ictx.Api, pluginkit.Route{
		OperationID: "testPluginLimited", Method: http.MethodGet, Path: "/test-plugin/limited/{id}", Access: pluginkit.Public,
		RateLimit: p.routeRule,
	}, func(ctx context.Context, _ *struct {
		ID string `path:"id"`
	}) (*pingOutput, error) {
		return p.ping(ctx, nil)
	})
	return nil
}
