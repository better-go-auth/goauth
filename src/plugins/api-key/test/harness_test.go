// Package test runs the api-key plugin end to end through a real goauth server (httptest), plus the Go
// API and the middlewares. Set GOAUTH_TEST_COLUMN_CASE=camel to run it on better-auth's column layout.
package test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	apikey "github.com/better-go-auth/goauth/src/plugins/api-key"
	apikeyconfig "github.com/better-go-auth/goauth/src/plugins/api-key/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

const password = "Password123!"

// fakeClock is a settable clock for expiry, refills and rate-limit windows.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *fakeClock { return &fakeClock{now: time.Now().UTC().Truncate(time.Millisecond)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// harness is a goauth server with the api-key plugin.
type harness struct {
	*compattest.Server
	plugin *apikey.Plugin
	clock  *fakeClock
}

// options of newHarness.
type harnessOpts struct {
	configs   []apikeyconfig.Configuration
	pluginOps []apikey.Option
	server    []compattest.Option
	configure []func(*config.AuthConfig)
	extra     func(h *harness) []compattest.Option
}

type harnessOpt func(*harnessOpts)

func withConfigs(cfgs ...apikeyconfig.Configuration) harnessOpt {
	return func(o *harnessOpts) { o.configs = cfgs }
}

func withPluginOptions(opts ...apikey.Option) harnessOpt {
	return func(o *harnessOpts) { o.pluginOps = append(o.pluginOps, opts...) }
}

func withServer(opts ...compattest.Option) harnessOpt {
	return func(o *harnessOpts) { o.server = append(o.server, opts...) }
}

func withAuthConfig(fn func(*config.AuthConfig)) harnessOpt {
	return func(o *harnessOpts) { o.configure = append(o.configure, fn) }
}

// newHarness starts goauth with the api-key plugin (one default configuration unless withConfigs).
func newHarness(t *testing.T, opts ...harnessOpt) *harness {
	t.Helper()
	o := harnessOpts{}
	for _, fn := range opts {
		fn(&o)
	}
	clock := newClock()
	pluginOpts := append([]apikey.Option{apikey.WithClock(clock.Now)}, o.pluginOps...)
	var p *apikey.Plugin
	if len(o.configs) <= 1 {
		cfg := apikeyconfig.Configuration{}
		if len(o.configs) == 1 {
			cfg = o.configs[0]
		}
		p = apikey.New(cfg, pluginOpts...)
	} else {
		var err error
		p, err = apikey.NewWithConfigurations(o.configs, pluginOpts...)
		if err != nil {
			t.Fatalf("NewWithConfigurations: %v", err)
		}
	}
	serverOpts := []compattest.Option{
		compattest.WithPlugin(p),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = "http://localhost:3000"
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
			for _, fn := range o.configure {
				fn(c)
			}
		}),
	}
	serverOpts = append(serverOpts, o.server...)
	s := compattest.NewServer(t, serverOpts...)
	// cookies are passed explicitly so several users can share one server
	s.Client.Jar = nil
	return &harness{Server: s, plugin: p, clock: clock}
}

var userSeq atomic.Int64

// user is a signed-up user with its session cookie.
type user struct {
	ID     string
	Email  string
	Cookie string
}

// signUp creates a user and returns its id and session cookie.
func (h *harness) signUp(t *testing.T) user {
	t.Helper()
	email := fmt.Sprintf("user%d-%d@example.com", userSeq.Add(1), time.Now().UnixNano())
	r := h.Post(t, "/api/auth/sign-up/email", map[string]any{"email": email, "password": password, "name": "Key User"})
	if r.Status != http.StatusOK {
		t.Fatalf("sign-up: %d %s", r.Status, r.Body)
	}
	var body struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	r.JSON(t, &body)
	ck := r.Cookie("better-auth.session_token")
	if ck == nil {
		t.Fatalf("sign-up set no session cookie: %v", r.Header)
	}
	return user{ID: body.User.ID, Email: email, Cookie: ck.Name + "=" + ck.Value}
}

// as returns headers carrying the user's session cookie (plus extra pairs).
func (u user) as(extra ...string) map[string]string {
	h := map[string]string{"Cookie": u.Cookie}
	for i := 0; i+1 < len(extra); i += 2 {
		h[extra[i]] = extra[i+1]
	}
	return h
}

// keyHeader returns an x-api-key header map.
func keyHeader(key string) map[string]string { return map[string]string{"x-api-key": key} }

// errBody is better-auth's error body.
type errBody struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details"`
}

// expectError checks the status, code and (when not empty) message of an error response.
func expectError(t *testing.T, r *compattest.Response, status int, code string, message ...string) errBody {
	t.Helper()
	if r.Status != status {
		t.Fatalf("status = %d, want %d (%s)", r.Status, status, r.Body)
	}
	var e errBody
	r.JSON(t, &e)
	if e.Code != code {
		t.Fatalf("code = %q, want %q (%s)", e.Code, code, r.Body)
	}
	if len(message) > 0 && e.Message != message[0] {
		t.Fatalf("message = %q, want %q", e.Message, message[0])
	}
	return e
}

// expectOK checks a 200 response and decodes it into v (when not nil).
func expectOK(t *testing.T, r *compattest.Response, v any) {
	t.Helper()
	if r.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", r.Status, r.Body)
	}
	if v != nil {
		r.JSON(t, v)
	}
}

// keyBody is the JSON of an API key.
type keyBody struct {
	ID                  string              `json:"id"`
	ConfigID            string              `json:"configId"`
	Name                *string             `json:"name"`
	Start               *string             `json:"start"`
	Prefix              *string             `json:"prefix"`
	Key                 string              `json:"key"`
	ReferenceID         string              `json:"referenceId"`
	RefillInterval      *float64            `json:"refillInterval"`
	RefillAmount        *float64            `json:"refillAmount"`
	LastRefillAt        *time.Time          `json:"lastRefillAt"`
	Enabled             bool                `json:"enabled"`
	RateLimitEnabled    bool                `json:"rateLimitEnabled"`
	RateLimitTimeWindow *float64            `json:"rateLimitTimeWindow"`
	RateLimitMax        *float64            `json:"rateLimitMax"`
	RequestCount        float64             `json:"requestCount"`
	Remaining           *float64            `json:"remaining"`
	LastRequest         *time.Time          `json:"lastRequest"`
	ExpiresAt           *time.Time          `json:"expiresAt"`
	CreatedAt           time.Time           `json:"createdAt"`
	UpdatedAt           time.Time           `json:"updatedAt"`
	Metadata            any                 `json:"metadata"`
	Permissions         map[string][]string `json:"permissions"`
}

// createKey creates a key over HTTP for u (body may be nil) and returns it.
func (h *harness) createKey(t *testing.T, u user, body map[string]any) keyBody {
	t.Helper()
	if body == nil {
		body = map[string]any{}
	}
	var k keyBody
	expectOK(t, h.Post(t, "/api/auth/api-key/create", body, u.as()), &k)
	return k
}

// rawKeys returns the keys of a JSON body as a sorted, comma-separated list.
func rawKeys(t *testing.T, raw []byte) string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode: %v (%s)", err, raw)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortStrings(keys)
	return strings.Join(keys, ",")
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func ptr[T any](v T) *T { return &v }
