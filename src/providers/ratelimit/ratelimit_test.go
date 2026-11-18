package ratelimit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
)

// fakeClock is a settable clock shared by the limiter and its memory storage.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newClock() *fakeClock { return &fakeClock{now: time.UnixMilli(1_700_000_000_000)} }

func req(path string) *http.Request { return httptest.NewRequest(http.MethodPost, path, nil) }

func TestWildcardMatch(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"/sign-in/*", "/sign-in/email", true},
		{"/sign-in/*", "/sign-in/", true},
		{"/sign-in/*", "/sign-in/email/extra", false},
		{"/sign-in/*", "/sign-up/email", false},
		{"/organization/**", "/organization/a/b/c", true},
		{"/organization/**", "/organization", true},
		// better-auth quirk kept on purpose: the separator before a trailing ** is optional
		{"/organization/**", "/organizations/a", true},
		{"/organization/**", "/org/a", false},
		{"/two-factor/verify-*", "/two-factor/verify-totp", true},
		{"/two-factor/verify-*", "/two-factor/enable", false},
		{"/a?c", "/abc", true},
		{"/a?c", "/abbc", false},
		{"/x.y/*", "/x.y/z", true},
		{"/x.y/*", "/xzy/z", false},
		{`/lit\*`, "/lit*", true},
		{`/lit\*`, "/litx", false},
		{"**", "/anything/at/all", true},
		{"/*/callback", "/google/callback", true},
	}
	for _, c := range cases {
		if got := WildcardMatch(c.pattern)(c.path); got != c.want {
			t.Errorf("WildcardMatch(%q)(%q) = %v, want %v (regexp %q)", c.pattern, c.path, got, c.want, wildcardRegexp(c.pattern))
		}
	}
}

func TestNormalizeIP(t *testing.T) {
	cases := []struct {
		ip     string
		subnet int
		want   string
	}{
		{"203.0.113.7", 64, "203.0.113.7"},
		{"::ffff:192.0.2.1", 64, "192.0.2.1"},
		{"2001:DB8::1", 64, "2001:0db8:0000:0000:0000:0000:0000:0000"},
		{"2001:db8:aaaa:bbbb:cccc::1", 48, "2001:0db8:aaaa:0000:0000:0000:0000:0000"},
		{"2001:db8::1", 128, "2001:0db8:0000:0000:0000:0000:0000:0001"},
		{"2001:db8::1", 0, "2001:0db8:0000:0000:0000:0000:0000:0000"},
		{"not-an-ip", 64, "not-an-ip"},
	}
	for _, c := range cases {
		if got := NormalizeIP(c.ip, c.subnet); got != c.want {
			t.Errorf("NormalizeIP(%q, %d) = %q, want %q", c.ip, c.subnet, got, c.want)
		}
	}
}

func TestResolveRuleOrder(t *testing.T) {
	l := New(Options{
		Enabled: true,
		Storage: NewMemoryStorage(),
		Global:  Rule{Window: 30 * time.Second, Max: 50},
		CustomRules: map[string]CustomRule{
			"/custom":            {Window: time.Minute, Max: 7},
			"/custom-max-only":   {Max: 9},
			"/off":               {Disabled: true},
			"/wild/*":            {Window: 2 * time.Second, Max: 2},
			"/sign-in/username":  {Max: 1},
			"/fn":                {Resolve: func(r *http.Request, cur Rule) (Rule, bool) { return Rule{Max: cur.Max * 2}, true }},
			"/fn-off":            {Resolve: func(*http.Request, Rule) (Rule, bool) { return Rule{}, false }},
			"/two-factor/enable": {Window: time.Hour},
		},
	})
	l.AddPluginRules(
		PathRule{PathMatcher: func(p string) bool { return p == "/sign-in/email-otp" }, Window: time.Minute, Max: 3},
		PathRule{PathMatcher: func(p string) bool { return len(p) > 11 && p[:12] == "/two-factor/" }, Window: 10 * time.Second, Max: 3},
		PathRule{PathMatcher: nil, Window: time.Second, Max: 1}, // ignored
	)
	cases := []struct {
		path string
		want Rule
		ok   bool
	}{
		{"/api/auth/get-session", Rule{30 * time.Second, 50}, true},
		{"/api/auth/sign-in/email", Rule{10 * time.Second, 3}, true},
		{"/api/auth/sign-up/email/", Rule{10 * time.Second, 3}, true},
		{"/api/auth/change-password", Rule{10 * time.Second, 3}, true},
		{"/api/auth/request-password-reset", Rule{60 * time.Second, 3}, true},
		{"/api/auth/forget-password/email-otp", Rule{60 * time.Second, 3}, true},
		{"/api/auth/sign-in/email-otp", Rule{time.Minute, 3}, true},
		{"/api/auth/two-factor/verify-totp", Rule{10 * time.Second, 3}, true},
		{"/api/auth/two-factor/enable", Rule{time.Hour, 3}, true},
		{"/api/auth/custom", Rule{time.Minute, 7}, true},
		{"/api/auth/custom-max-only", Rule{30 * time.Second, 9}, true},
		{"/api/auth/sign-in/username", Rule{10 * time.Second, 1}, true},
		{"/api/auth/wild/thing", Rule{2 * time.Second, 2}, true},
		{"/api/auth/fn", Rule{30 * time.Second, 100}, true},
		{"/api/auth/off", Rule{}, false},
		{"/api/auth/fn-off", Rule{}, false},
	}
	for _, c := range cases {
		key, rule, ok := l.Resolve(req(c.path), "1.2.3.4")
		if ok != c.ok || rule != c.want {
			t.Errorf("%s: rule=%+v ok=%v, want %+v ok=%v", c.path, rule, ok, c.want, c.ok)
		}
		if ok && key != "1.2.3.4|"+l.Path(c.path) {
			t.Errorf("%s: key %q", c.path, key)
		}
	}
	// without a client IP better-auth does not rate limit
	if _, _, ok := l.Resolve(req("/api/auth/sign-in/email"), ""); ok {
		t.Fatal("request without IP must not be limited")
	}
}

func TestPathNormalization(t *testing.T) {
	l := New(Options{BasePath: "/auth/"})
	for in, want := range map[string]string{
		"/auth":                "/",
		"/auth/":               "/",
		"/auth/sign-in/email/": "/sign-in/email",
		"/other/x":             "/other/x",
		"/authx/y":             "/authx/y",
	} {
		if got := l.Path(in); got != want {
			t.Errorf("Path(%q) = %q, want %q", in, got, want)
		}
	}
	if New(Options{BasePath: "/"}).Path("/a/b/") != "/a/b" {
		t.Fatal("root base path")
	}
}

// TestCheckAndHit walks better-auth's onRequest/onResponse sequence with a fake clock.
func TestCheckAndHit(t *testing.T) {
	clock := newClock()
	store := NewMemoryStorage().WithClock(clock.Now)
	l := New(Options{Enabled: true, Storage: store, Now: clock.Now})
	ctx := context.Background()
	rule := Rule{Window: 10 * time.Second, Max: 3}
	key := Key("1.2.3.4", "/sign-in/email")

	// Step 1: three answered requests
	for i := 0; i < 3; i++ {
		if limited, _ := l.Check(ctx, key, rule); limited {
			t.Fatalf("request %d limited", i+1)
		}
		l.Hit(ctx, key, rule)
		clock.Add(time.Second)
	}
	// Step 2: the fourth is rejected; retry = ceil((last + 10s - now)/1s) = 9 (last request 1s ago)
	limited, retry := l.Check(ctx, key, rule)
	if !limited || retry != 9 {
		t.Fatalf("4th: limited=%v retry=%d", limited, retry)
	}
	// Step 3: other keys are independent
	if limited, _ := l.Check(ctx, Key("5.6.7.8", "/sign-in/email"), rule); limited {
		t.Fatal("other IP limited")
	}
	// Step 4: half a second later the retry rounds up
	clock.Add(500 * time.Millisecond)
	if _, retry := l.Check(ctx, key, rule); retry != 9 {
		t.Fatalf("retry after 1.5s = %d, want 9 (ceil 8.5)", retry)
	}
	// Step 5: once the window since the last request passed, the record restarts at 1
	clock.Add(9 * time.Second)
	if limited, _ := l.Check(ctx, key, rule); limited {
		t.Fatal("still limited after the window")
	}
	l.Hit(ctx, key, rule)
	rec, _ := store.Get(ctx, key)
	if rec == nil || rec.Count != 1 || rec.Key != key || rec.LastRequest != clock.Now().UnixMilli() {
		t.Fatalf("record after reset: %+v", rec)
	}
}

// TestSlidingLastRequest: like better-auth, every counted request moves lastRequest, so a client that keeps
// hammering inside the window stays limited only while it keeps being counted.
func TestSlidingLastRequest(t *testing.T) {
	clock := newClock()
	l := New(Options{Enabled: true, Storage: NewMemoryStorage().WithClock(clock.Now), Now: clock.Now})
	ctx := context.Background()
	rule := Rule{Window: 10 * time.Second, Max: 2}
	key := "k"
	l.Hit(ctx, key, rule)
	clock.Add(9 * time.Second)
	l.Hit(ctx, key, rule) // count 2, lastRequest moved
	clock.Add(9 * time.Second)
	// 18s after the first request but only 9s after the last: still limited
	if limited, retry := l.Check(ctx, key, rule); !limited || retry != 1 {
		t.Fatalf("limited=%v retry=%d", limited, retry)
	}
}

func TestMemoryStorageExpiry(t *testing.T) {
	clock := newClock()
	m := NewMemoryStorage().WithClock(clock.Now)
	ctx := context.Background()
	_ = m.Set(ctx, "a", Record{Key: "a", Count: 1}, false, 10*time.Second)
	_ = m.Set(ctx, "b", Record{Key: "b", Count: 1}, false, time.Hour)
	clock.Add(10 * time.Second)
	if rec, _ := m.Get(ctx, "a"); rec != nil {
		t.Fatalf("expired record returned: %+v", rec)
	}
	if rec, _ := m.Get(ctx, "b"); rec == nil {
		t.Fatal("live record missing")
	}
	// a write after the sweep interval removes expired entries
	_ = m.Set(ctx, "c", Record{}, false, time.Second)
	clock.Add(2 * time.Minute)
	_ = m.Set(ctx, "d", Record{}, false, time.Hour)
	if n := m.Len(); n != 2 { // b and d
		t.Fatalf("Len after sweep = %d", n)
	}
}

// TestSecondaryStorageFormat: the key and JSON value are exactly better-auth's, so a TypeScript server
// sharing the store reads and writes the same records.
func TestSecondaryStorageFormat(t *testing.T) {
	store := memory.New()
	s := NewSecondaryStorage(store)
	ctx := context.Background()
	l := New(Options{Enabled: true, Storage: s})
	key := Key("10.0.0.1", "/sign-in/email")
	l.Hit(ctx, key, Rule{Window: 10 * time.Second, Max: 3})

	raw, ok, err := store.Get(ctx, "10.0.0.1|/sign-in/email")
	if err != nil || !ok {
		t.Fatalf("record not stored under the better-auth key: ok=%v err=%v", ok, err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw.(string)), &m); err != nil {
		t.Fatalf("value is not JSON: %v", raw)
	}
	if m["key"] != key || m["count"] != float64(1) || m["lastRequest"] == nil || len(m) != 3 {
		t.Fatalf("value = %v", m)
	}
	// a record written by better-auth (JSON string) is read back
	_ = store.Set(ctx, "ts|/x", `{"key":"ts|/x","count":5,"lastRequest":1700000000000}`, time.Minute)
	rec, err := s.Get(ctx, "ts|/x")
	if err != nil || rec == nil || rec.Count != 5 || rec.LastRequest != 1700000000000 {
		t.Fatalf("read TS record: %+v %v", rec, err)
	}
	// invalid JSON is treated as no record (safeJSONParse)
	_ = store.Set(ctx, "bad", "{not json", time.Minute)
	if rec, err := s.Get(ctx, "bad"); rec != nil || err != nil {
		t.Fatalf("bad record: %+v %v", rec, err)
	}
}

// errStorage fails every call.
type errStorage struct{}

func (errStorage) Get(context.Context, string) (*Record, error) { return nil, errors.New("down") }
func (errStorage) Set(context.Context, string, Record, bool, time.Duration) error {
	return errors.New("down")
}

func TestStorageErrorsLetRequestsThrough(t *testing.T) {
	var reported int
	l := New(Options{Enabled: true, Storage: errStorage{}, OnError: func(error) { reported++ }})
	ctx := context.Background()
	if limited, _ := l.Check(ctx, "k", Rule{Window: time.Second, Max: 1}); limited {
		t.Fatal("storage error must not limit")
	}
	l.Hit(ctx, "k", Rule{Window: time.Second, Max: 1})
	if reported != 2 {
		t.Fatalf("reported %d errors, want 2", reported)
	}
}

// TestConcurrentHits: Hit serializes updates of one key, so no request is lost.
func TestConcurrentHits(t *testing.T) {
	store := NewMemoryStorage()
	l := New(Options{Enabled: true, Storage: store})
	ctx := context.Background()
	rule := Rule{Window: time.Minute, Max: 1000}
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.Hit(ctx, "same", rule)
		}()
	}
	wg.Wait()
	rec, _ := store.Get(ctx, "same")
	if rec == nil || rec.Count != 64 {
		t.Fatalf("count = %+v, want 64", rec)
	}
	if len(l.locks.locks) != 0 {
		t.Fatalf("key locks leaked: %d", len(l.locks.locks))
	}
}

func TestDisabledWithoutStorage(t *testing.T) {
	if New(Options{Enabled: true}).Enabled() {
		t.Fatal("a limiter without storage cannot be enabled")
	}
	var nilLimiter *Limiter
	nilLimiter.AddPluginRules(PathRule{PathMatcher: func(string) bool { return true }, Window: time.Second, Max: 1})
	if nilLimiter.Enabled() {
		t.Fatal("nil limiter enabled")
	}
}
