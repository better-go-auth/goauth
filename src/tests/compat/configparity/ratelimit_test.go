package configparity

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/providers/ratelimit"
	"github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestRateLimitSignInSpecialRule: /sign-in/* allows 3 requests per 10 s per IP; the 4th gets better-auth's
// exact 429. Other IPs and other paths are counted separately.
func TestRateLimitSignInSpecialRule(t *testing.T) {
	s := compattest.NewServer(t, enabled())
	signUp(t, s, "rl@example.com")

	// Step 1: three answered sign-ins (wrong password: failed requests count too)
	for i := 0; i < 3; i++ {
		if res := signIn(t, s, "rl@example.com", "wrong-password", "203.0.113.1"); res.Status != http.StatusUnauthorized {
			t.Fatalf("sign-in %d: %d %s", i+1, res.Status, res.Body)
		}
	}
	// Step 2: the 4th, even with the right password, is rejected before the endpoint runs
	expect429(t, signIn(t, s, "rl@example.com", password, "203.0.113.1"), 10)
	// Step 3: another client IP has its own counter
	if res := signIn(t, s, "rl@example.com", password, "203.0.113.2"); res.Status != http.StatusOK {
		t.Fatalf("other IP: %d %s", res.Status, res.Body)
	}
	// Step 4: other paths keep the global rule (100 / 10 s)
	for i := 0; i < 5; i++ {
		if res := s.Get(t, "/api/auth/ok", map[string]string{"X-Forwarded-For": "203.0.113.1"}); res.Status != http.StatusOK {
			t.Fatalf("/ok %d: %d", i+1, res.Status)
		}
	}
}

// TestRateLimitIPv6Subnet: IPv6 clients of one /64 share a counter (better-auth's normalizeIP).
func TestRateLimitIPv6Subnet(t *testing.T) {
	s := compattest.NewServer(t, enabled())
	signUp(t, s, "v6@example.com")
	for i, ip := range []string{"2001:db8:1:2::1", "2001:db8:1:2::2", "2001:db8:1:2:aaaa::3"} {
		if res := signIn(t, s, "v6@example.com", password, ip); res.Status != http.StatusOK {
			t.Fatalf("sign-in %d: %d", i+1, res.Status)
		}
	}
	expect429(t, signIn(t, s, "v6@example.com", password, "2001:db8:1:2:ffff::9"), 10)
	if res := signIn(t, s, "v6@example.com", password, "2001:db8:1:3::1"); res.Status != http.StatusOK {
		t.Fatalf("other /64: %d", res.Status)
	}
}

// TestRateLimitWindowReset: after the window the client may send again.
func TestRateLimitWindowReset(t *testing.T) {
	s := compattest.NewServer(t, enabled(func(c *config.AuthConfig) {
		c.RateLimit.CustomRules = map[string]ratelimit.CustomRule{"/ok": {Window: time.Second, Max: 1}}
	}))
	if res := s.Get(t, "/api/auth/ok"); res.Status != http.StatusOK {
		t.Fatalf("first: %d", res.Status)
	}
	expect429(t, s.Get(t, "/api/auth/ok"), 1)
	time.Sleep(1100 * time.Millisecond)
	if res := s.Get(t, "/api/auth/ok"); res.Status != http.StatusOK {
		t.Fatalf("after the window: %d %s", res.Status, res.Body)
	}
}

// TestRateLimitGlobalAndCustomRules: RateLimit.Max is the default rule; custom rules override it, turn
// limiting off (also for special-rule paths) and match wildcard patterns.
func TestRateLimitGlobalAndCustomRules(t *testing.T) {
	var resolved []ratelimit.Rule
	s := compattest.NewServer(t, enabled(func(c *config.AuthConfig) {
		c.RateLimit.Max = 2
		c.RateLimit.CustomRules = map[string]ratelimit.CustomRule{
			"/sign-in/*":   {Disabled: true},
			"/list-*":      {Max: 4},
			"/get-session": {Max: 1},
			"/ok-fn-off":   {Resolve: func(*http.Request, ratelimit.Rule) (ratelimit.Rule, bool) { return ratelimit.Rule{}, false }},
			"/update-session": {Resolve: func(r *http.Request, cur ratelimit.Rule) (ratelimit.Rule, bool) {
				resolved = append(resolved, cur)
				// per-request rule: clients sending X-Premium get more
				if r.Header.Get("X-Premium") != "" {
					return ratelimit.Rule{Max: 50}, true
				}
				return ratelimit.Rule{Max: 1}, true
			}},
		}
	}))
	signUp(t, s, "custom@example.com")

	// global rule (Max 2) on /ok
	s.Get(t, "/api/auth/ok")
	s.Get(t, "/api/auth/ok")
	expect429(t, s.Get(t, "/api/auth/ok"), 10)

	// "/sign-in/*": disabled although /sign-in has a special rule
	for i := 0; i < 6; i++ {
		if res := signIn(t, s, "custom@example.com", password, "198.51.100.7"); res.Status != http.StatusOK {
			t.Fatalf("sign-in %d with limiting disabled: %d", i+1, res.Status)
		}
	}

	// exact path rule
	if res := s.Get(t, "/api/auth/get-session"); res.Status != http.StatusOK {
		t.Fatalf("get-session: %d", res.Status)
	}
	expect429(t, s.Get(t, "/api/auth/get-session"), 10)

	// wildcard rule: 4 list-sessions requests
	for i := 0; i < 4; i++ {
		if res := s.Get(t, "/api/auth/list-sessions"); res.Status == http.StatusTooManyRequests {
			t.Fatalf("list-sessions %d limited", i+1)
		}
	}
	expect429(t, s.Get(t, "/api/auth/list-sessions"), 10)

	// function rule: receives the rule resolved so far and decides per request
	body := map[string]any{}
	if res := s.Post(t, "/api/auth/update-session", body); res.Status == http.StatusTooManyRequests {
		t.Fatalf("update-session 1 limited")
	}
	expect429(t, s.Post(t, "/api/auth/update-session", body), 10)
	if res := s.Post(t, "/api/auth/update-session", body, map[string]string{"X-Premium": "1"}); res.Status == http.StatusTooManyRequests {
		t.Fatal("premium request limited")
	}
	if len(resolved) == 0 || resolved[0] != (ratelimit.Rule{Window: 10 * time.Second, Max: 2}) {
		t.Fatalf("Resolve got %+v, want the global rule", resolved)
	}
}

// TestRateLimitDefaultsOnlyInProduction: like better-auth, the limiter is on by default only in production.
func TestRateLimitDefaultsOnlyInProduction(t *testing.T) {
	// Step 1: development: no limit
	dev := compattest.NewServer(t)
	signUp(t, dev, "dev@example.com")
	for i := 0; i < 6; i++ {
		if res := signIn(t, dev, "dev@example.com", password, "192.0.2.1"); res.Status != http.StatusOK {
			t.Fatalf("dev sign-in %d: %d", i+1, res.Status)
		}
	}
	if dev.Auth.RateLimiter().Enabled() {
		t.Fatal("limiter enabled outside production")
	}
	// Step 2: production: on without any option
	t.Setenv("GOAUTH_ENV", "production")
	prod := compattest.NewServer(t, compattest.WithConfig(func(c *config.AuthConfig) { c.Secret = prodSecret }))
	signUp(t, prod, "prod@example.com")
	for i := 0; i < 2; i++ {
		signIn(t, prod, "prod@example.com", password, "192.0.2.1")
	}
	// sign-up counted under /sign-up/email, so sign-in still has its 3rd request
	if res := signIn(t, prod, "prod@example.com", password, "192.0.2.1"); res.Status != http.StatusOK {
		t.Fatalf("3rd prod sign-in: %d", res.Status)
	}
	expect429(t, signIn(t, prod, "prod@example.com", password, "192.0.2.1"), 10)
	// Step 3: production with Enabled = false
	off := compattest.NewServer(t, compattest.WithConfig(func(c *config.AuthConfig) {
		c.Secret = prodSecret
		c.RateLimit.Enabled = new(false)
	}))
	for i := 0; i < 5; i++ {
		if res := off.Get(t, "/api/auth/ok"); res.Status != http.StatusOK {
			t.Fatalf("disabled in production %d: %d", i+1, res.Status)
		}
	}
}

// TestRateLimitSecondaryStorageShared: two servers on one secondary storage share the counters, stored
// exactly like better-auth ("<ip>|<path>" → {"key","count","lastRequest"}).
func TestRateLimitSecondaryStorageShared(t *testing.T) {
	store := memory.New()
	a := compattest.NewServer(t, enabled(), compattest.WithSecondaryStorage(store))
	b := compattest.NewServer(t, enabled(), compattest.WithSecondaryStorage(store))
	signUp(t, a, "shared@example.com")

	// Step 1: two sign-ins on A, one on B: the limit of 3 is reached across both
	signIn(t, a, "shared@example.com", "wrong", "198.51.100.20")
	signIn(t, a, "shared@example.com", "wrong", "198.51.100.20")
	signIn(t, b, "shared@example.com", "wrong", "198.51.100.20")
	expect429(t, signIn(t, a, "shared@example.com", password, "198.51.100.20"), 10)
	expect429(t, signIn(t, b, "shared@example.com", password, "198.51.100.20"), 10)

	// Step 2: the record has better-auth's key and JSON shape
	raw, ok, err := store.Get(context.Background(), "198.51.100.20|/sign-in/email")
	if err != nil || !ok {
		t.Fatalf("record missing: ok=%v err=%v", ok, err)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(raw.(string)), &rec); err != nil {
		t.Fatalf("record is not JSON: %v", raw)
	}
	if rec["key"] != "198.51.100.20|/sign-in/email" || rec["count"] != float64(3) {
		t.Fatalf("record = %v", rec)
	}
	if a.Auth.RateLimiter().Storage() == nil {
		t.Fatal("no storage")
	}
}

// TestRateLimitPluginRules: a plugin's RateLimitRules (prefix rule) and a pluginkit.Route.RateLimit rule
// (path with a parameter) apply through the global limiter.
func TestRateLimitPluginRules(t *testing.T) {
	p := &testPlugin{
		id: "test-plugin",
		rules: []ratelimit.PathRule{{
			PathMatcher: func(path string) bool { return strings.HasPrefix(path, "/test-plugin/ping") },
			Window:      time.Minute, Max: 2,
		}},
		routeRule: &ratelimit.Rule{Window: time.Minute, Max: 1},
	}
	s := compattest.NewServer(t, enabled(), compattest.WithPlugin(p))
	s.Get(t, "/api/auth/test-plugin/ping")
	s.Get(t, "/api/auth/test-plugin/ping")
	expect429(t, s.Get(t, "/api/auth/test-plugin/ping"), 60)

	// route rule: one request per path (each path value has its own key)
	if res := s.Get(t, "/api/auth/test-plugin/limited/a"); res.Status != http.StatusOK {
		t.Fatalf("limited/a: %d", res.Status)
	}
	expect429(t, s.Get(t, "/api/auth/test-plugin/limited/a"), 60)
	if res := s.Get(t, "/api/auth/test-plugin/limited/b"); res.Status != http.StatusOK {
		t.Fatalf("limited/b: %d", res.Status)
	}
	// the endpoint never ran for rejected requests
	if p.pingCount() != 4 {
		t.Fatalf("plugin endpoint ran %d times, want 4", p.pingCount())
	}
}

// TestRateLimitWithoutClientIP: with IP tracking disabled there is no key, so nothing is limited
// (better-auth skips rate limiting when it cannot determine the IP).
func TestRateLimitWithoutClientIP(t *testing.T) {
	s := compattest.NewServer(t, enabled(func(c *config.AuthConfig) { c.Advanced.IPAddress.DisableTracking = true }))
	for i := 0; i < 5; i++ {
		if res := s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "x@example.com", "password": "nope-nope"}); res.Status == http.StatusTooManyRequests {
			t.Fatalf("request %d limited without an IP", i+1)
		}
	}
}

// TestRateLimitStorageOptions: storage selection and errors at setup.
func TestRateLimitStorageOptions(t *testing.T) {
	setup := func(t *testing.T, mutate func(*goauth.GoAuthOptions)) (*goauth.GoAuth, error) {
		db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
		if err != nil {
			t.Fatal(err)
		}
		o := goauth.GoAuthOptions{Conn: db, AuthConfig: config.AuthConfig{BaseURL: "http://localhost:3000", Secret: compattest.TestSecret}}
		mutate(&o)
		return goauth.SetupGoAuth(context.Background(), humago.New(http.NewServeMux(), huma.DefaultConfig("t", "1")), o)
	}
	t.Run("database is rejected until the rateLimit table exists", func(t *testing.T) {
		_, err := setup(t, func(o *goauth.GoAuthOptions) { o.RateLimit.Storage = ratelimit.StorageDatabase })
		if err == nil || !strings.Contains(err.Error(), "not supported yet") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("secondary-storage needs a secondary storage", func(t *testing.T) {
		_, err := setup(t, func(o *goauth.GoAuthOptions) { o.RateLimit.Storage = ratelimit.StorageSecondaryStorage })
		if err == nil {
			t.Fatal("expected an error")
		}
	})
	t.Run("unknown storage", func(t *testing.T) {
		if _, err := setup(t, func(o *goauth.GoAuthOptions) { o.RateLimit.Storage = "redis" }); err == nil {
			t.Fatal("expected an error")
		}
	})
	t.Run("default is memory without a secondary storage", func(t *testing.T) {
		a, err := setup(t, func(*goauth.GoAuthOptions) {})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := a.RateLimiter().Storage().(*ratelimit.MemoryStorage); !ok {
			t.Fatalf("storage = %T", a.RateLimiter().Storage())
		}
	})
	t.Run("default is secondary-storage when one is configured", func(t *testing.T) {
		a, err := setup(t, func(o *goauth.GoAuthOptions) { o.SecondaryStorage = memory.New() })
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := a.RateLimiter().Storage().(*ratelimit.SecondaryStorage); !ok {
			t.Fatalf("storage = %T", a.RateLimiter().Storage())
		}
	})
	t.Run("custom storage wins", func(t *testing.T) {
		custom := ratelimit.NewMemoryStorage()
		a, err := setup(t, func(o *goauth.GoAuthOptions) {
			o.RateLimit.Storage = ratelimit.StorageDatabase
			o.RateLimit.CustomStorage = custom
		})
		if err != nil {
			t.Fatal(err)
		}
		if a.RateLimiter().Storage() != custom {
			t.Fatal("custom storage not used")
		}
	})
}
