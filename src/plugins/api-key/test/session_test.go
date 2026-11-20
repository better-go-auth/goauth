package test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	apikey "github.com/better-go-auth/goauth/src/plugins/api-key"
	apikeyconfig "github.com/better-go-auth/goauth/src/plugins/api-key/config"
	"github.com/better-go-auth/goauth/src/providers/authenticator"
	"github.com/danielgtaylor/huma/v2"
)

type sessionBody struct {
	Session struct {
		ID        string    `json:"id"`
		Token     string    `json:"token"`
		UserID    string    `json:"userId"`
		UserAgent *string   `json:"userAgent"`
		ExpiresAt time.Time `json:"expiresAt"`
	} `json:"session"`
	User struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
}

func TestSessionFromAPIKey(t *testing.T) {
	h := newHarness(t, withConfigs(apikeyconfig.Configuration{EnableSessionForAPIKeys: true}))
	u := h.signUp(t)
	k := h.createKey(t, u, nil)
	// Step 1: GET /get-session answers with the mocked session (id = key id, token = key)
	r := h.Get(t, "/api/auth/get-session", map[string]string{"x-api-key": k.Key, "User-Agent": "key-client/1.0"})
	var s sessionBody
	expectOK(t, r, &s)
	if s.Session.ID != k.ID || s.Session.Token != k.Key || s.Session.UserID != u.ID || s.User.ID != u.ID || s.User.Email != u.Email ||
		s.Session.UserAgent == nil || *s.Session.UserAgent != "key-client/1.0" {
		t.Fatalf("session = %s", r.Body)
	}
	// better-auth adds session.expiresIn (seconds) as milliseconds: 7 days → ~10 minutes
	if d := s.Session.ExpiresAt.Sub(h.clock.Now()); d < 10*time.Minute || d > 11*time.Minute {
		t.Fatalf("mock expiresAt in %v", d)
	}
	// Step 2: session-protected core and plugin routes accept the key
	expectOK(t, h.Get(t, "/api/auth/list-sessions", keyHeader(k.Key)), nil)
	var list struct {
		Total int `json:"total"`
	}
	expectOK(t, h.Get(t, "/api/auth/api-key/list", keyHeader(k.Key)), &list)
	if list.Total != 1 {
		t.Fatalf("list via key = %d", list.Total)
	}
	// a key can create another key for its owner
	var created keyBody
	expectOK(t, h.Post(t, "/api/auth/api-key/create", map[string]any{"name": "child"}, keyHeader(k.Key)), &created)
	if created.ReferenceID != u.ID {
		t.Fatalf("child owner = %s", created.ReferenceID)
	}
	// Step 3: every use counts against the key's rate limit (default 10 per day)
	got, _ := h.plugin.GetAPIKey(context.Background(), k.ID, "", u.ID)
	if got.RequestCount != 4 {
		t.Fatalf("requestCount = %d, want 4", got.RequestCount)
	}
	// Step 4: no key: no session
	r = h.Get(t, "/api/auth/get-session")
	if r.Status != 200 || strings.TrimSpace(string(r.Body)) != "null" {
		t.Fatalf("anonymous get-session = %d %s", r.Status, r.Body)
	}
}

func TestSessionFromAPIKeyErrors(t *testing.T) {
	h := newHarness(t, withConfigs(apikeyconfig.Configuration{
		EnableSessionForAPIKeys: true, APIKeyHeaders: []string{"x-api-key", "x-alt-key"},
		RateLimit: apikeyconfig.RateLimit{MaxRequests: ptr(2), TimeWindow: time.Minute},
	}))
	u := h.signUp(t)
	k := h.createKey(t, u, nil)
	// Step 1: a key shorter than DefaultKeyLength: 403 INVALID_API_KEY, even on public routes
	expectError(t, h.Get(t, "/api/auth/get-session", keyHeader("short")), http.StatusForbidden, "INVALID_API_KEY", "Invalid API key.")
	expectError(t, h.Get(t, "/api/auth/ok", keyHeader("short")), http.StatusForbidden, "INVALID_API_KEY")
	// Step 2: an unknown key of the right length: 401 INVALID_API_KEY
	expectError(t, h.Get(t, "/api/auth/get-session", keyHeader(strings.Repeat("a", 64))), http.StatusUnauthorized, "INVALID_API_KEY")
	// Step 3: the second header works too; the rate limit (2 per minute) answers 429 RATE_LIMITED
	expectOK(t, h.Get(t, "/api/auth/get-session", map[string]string{"x-alt-key": k.Key}), nil)
	expectOK(t, h.Get(t, "/api/auth/get-session", keyHeader(k.Key)), nil)
	e := expectError(t, h.Get(t, "/api/auth/get-session", keyHeader(k.Key)), http.StatusTooManyRequests, "RATE_LIMITED", "Rate limit exceeded.")
	if e.Details["tryAgainIn"] == nil {
		t.Fatalf("details = %v", e.Details)
	}
	// Step 4: disabled and expired keys
	h.clock.Advance(2 * time.Minute)
	expectOK(t, h.Post(t, "/api/auth/api-key/update", map[string]any{"keyId": k.ID, "enabled": false}, u.as()), nil)
	expectError(t, h.Get(t, "/api/auth/get-session", keyHeader(k.Key)), http.StatusUnauthorized, "KEY_DISABLED")
	exp := h.serverKey(t, apikey.CreateAPIKeyInput{UserID: &u.ID, ExpiresIn: ptr(float64(86400))})
	h.clock.Advance(86401 * time.Second)
	expectError(t, h.Get(t, "/api/auth/get-session", keyHeader(exp.Key)), http.StatusUnauthorized, "KEY_EXPIRED")
	// Step 5: a key whose owner is gone: INVALID_REFERENCE_ID_FROM_API_KEY
	ghost := "ghost-user-id"
	gk := h.serverKey(t, apikey.CreateAPIKeyInput{UserID: &ghost})
	expectError(t, h.Get(t, "/api/auth/get-session", keyHeader(gk.Key)), http.StatusUnauthorized, "INVALID_REFERENCE_ID_FROM_API_KEY",
		"The reference id from the API key is invalid.")
}

func TestSessionCustomGetterAndValidator(t *testing.T) {
	h := newHarness(t, withConfigs(apikeyconfig.Configuration{
		EnableSessionForAPIKeys: true,
		CustomAPIKeyGetter: func(r *http.Request) string {
			return strings.TrimPrefix(r.Header.Get("Authorization"), "ApiKey ")
		},
		CustomAPIKeyValidator: func(_ context.Context, key string) (bool, error) { return !strings.HasSuffix(key, "Z"), nil },
	}))
	u := h.signUp(t)
	var k keyBody
	for {
		k = h.createKey(t, u, nil)
		if !strings.HasSuffix(k.Key, "Z") {
			break
		}
	}
	var s sessionBody
	expectOK(t, h.Get(t, "/api/auth/get-session", map[string]string{"Authorization": "ApiKey " + k.Key}), &s)
	if s.User.ID != u.ID {
		t.Fatalf("session user = %s", s.User.ID)
	}
	// the validator rejects keys ending in Z with 403 INVALID_API_KEY
	expectError(t, h.Get(t, "/api/auth/get-session", map[string]string{"Authorization": "ApiKey " + strings.Repeat("a", 63) + "Z"}),
		http.StatusForbidden, "INVALID_API_KEY")
}

// TestNoSessionWithoutOption checks keys are ignored by goauth routes unless EnableSessionForAPIKeys.
func TestNoSessionWithoutOption(t *testing.T) {
	h := newHarness(t)
	u := h.signUp(t)
	k := h.createKey(t, u, nil)
	r := h.Get(t, "/api/auth/get-session", keyHeader(k.Key))
	if r.Status != 200 || strings.TrimSpace(string(r.Body)) != "null" {
		t.Fatalf("get-session = %d %s", r.Status, r.Body)
	}
	expectError(t, h.Get(t, "/api/auth/list-sessions", keyHeader("short")), 401, "UNAUTHORIZED")
}

// meRoute registers a protected Huma route of the host application.
func meRoute(h *harness, mw func(huma.Context, func(huma.Context))) {
	huma.Register(h.API, huma.Operation{
		OperationID: "apiKeyMe", Method: http.MethodGet, Path: "/api/app/me",
		Middlewares: huma.Middlewares{mw, h.Auth.MiddlewareInt().Authenticate()},
	}, func(ctx context.Context, _ *struct{}) (*struct {
		Body map[string]any
	}, error) {
		out := &struct{ Body map[string]any }{Body: map[string]any{}}
		if s, ok := authenticator.SessionFromContext(ctx); ok {
			out.Body["userId"] = s.User.ID
		}
		if k, ok := apikey.FromContext(ctx); ok {
			out.Body["keyId"] = k.ID
		}
		if sw, ok := apikey.SessionFromContext(ctx); ok {
			out.Body["sessionToken"] = sw.Session.Token
		}
		return out, nil
	})
}

func TestHostMiddleware(t *testing.T) {
	// sessions for goauth routes are off: the middleware works on its own
	h := newHarness(t)
	meRoute(h, h.plugin.Middleware(apikey.MiddlewareOptions{}))
	u := h.signUp(t)
	k := h.createKey(t, u, nil)
	// Step 1: the key authenticates the route; goauth's Authenticate middleware sees the session
	var me map[string]any
	expectOK(t, h.Get(t, "/api/app/me", keyHeader(k.Key)), &me)
	if me["userId"] != u.ID || me["keyId"] != k.ID || me["sessionToken"] != k.Key {
		t.Fatalf("me = %v", me)
	}
	// Step 2: no key, wrong key
	expectError(t, h.Get(t, "/api/app/me"), 401, "UNAUTHORIZED")
	expectError(t, h.Get(t, "/api/app/me", keyHeader(strings.Repeat("b", 64))), 401, "INVALID_API_KEY")
	expectError(t, h.Get(t, "/api/app/me", keyHeader("tiny")), 403, "INVALID_API_KEY")
}

func TestHTTPMiddlewarePermissions(t *testing.T) {
	h := newHarness(t)
	u := h.signUp(t)
	reader := h.serverKey(t, apikey.CreateAPIKeyInput{UserID: &u.ID, Permissions: map[string][]string{"reports": {"read"}}})
	writer := h.serverKey(t, apikey.CreateAPIKeyInput{UserID: &u.ID, Permissions: map[string][]string{"reports": {"read", "write"}}})
	handler := h.plugin.HTTPMiddleware(apikey.MiddlewareOptions{Permissions: map[string][]string{"reports": {"write"}}})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			k, _ := apikey.FromContext(r.Context())
			_ = json.NewEncoder(w).Encode(map[string]string{"keyId": k.ID})
		}))
	srv := httptest.NewServer(handler)
	defer srv.Close()
	call := func(key string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		if key != "" {
			req.Header.Set("x-api-key", key)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	// Step 1: the writer passes, the reader lacks reports:write (401 KEY_NOT_FOUND like better-auth)
	if st, body := call(writer.Key); st != 200 || !strings.Contains(body, writer.ID) {
		t.Fatalf("writer = %d %s", st, body)
	}
	if st, body := call(reader.Key); st != 401 || !strings.Contains(body, `"KEY_NOT_FOUND"`) {
		t.Fatalf("reader = %d %s", st, body)
	}
	if st, _ := call(""); st != 401 {
		t.Fatalf("no key = %d", st)
	}
	// Step 2: Optional lets anonymous requests through
	opt := httptest.NewServer(h.plugin.HTTPMiddleware(apikey.MiddlewareOptions{Optional: true})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := apikey.FromContext(r.Context())
		if ok {
			w.WriteHeader(202)
		}
	})))
	defer opt.Close()
	res, err := http.Get(opt.URL)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("optional anonymous = %v %v", res, err)
	}
	res.Body.Close()
}
