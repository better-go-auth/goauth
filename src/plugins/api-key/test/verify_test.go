package test

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/config"
	apikey "github.com/better-go-auth/goauth/src/plugins/api-key"
	apikeyconfig "github.com/better-go-auth/goauth/src/plugins/api-key/config"
)

// verify calls the server-only VerifyAPIKey.
func (h *harness) verify(t *testing.T, key string, perms map[string][]string) *apikey.VerifyAPIKeyResult {
	t.Helper()
	res, err := h.plugin.VerifyAPIKey(context.Background(), apikey.VerifyAPIKeyInput{Key: key, Permissions: perms})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return res
}

// expectInvalid checks a failed verification's code and message.
func expectInvalid(t *testing.T, res *apikey.VerifyAPIKeyResult, code, message string) {
	t.Helper()
	if res.Valid || res.Key != nil || res.Error == nil || res.Error.Code != code || res.Error.Message != message {
		raw, _ := json.Marshal(res)
		t.Fatalf("result = %s, want %s %q", raw, code, message)
	}
}

// serverKey creates a key through the Go API for u.
func (h *harness) serverKey(t *testing.T, in apikey.CreateAPIKeyInput) *apikey.CreateAPIKeyResponse {
	t.Helper()
	k, err := h.plugin.CreateAPIKey(context.Background(), in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return k
}

func TestVerifyBasics(t *testing.T) {
	h := newHarness(t, withConfigs(apikeyconfig.Configuration{EnableMetadata: true}))
	u := h.signUp(t)
	k := h.createKey(t, u, map[string]any{"metadata": map[string]any{"tier": "gold"}})
	// Step 1: a valid key: {valid: true, error: null, key} without the key value
	res := h.verify(t, k.Key, nil)
	if !res.Valid || res.Error != nil || res.Key == nil || res.Key.ID != k.ID || res.Key.Metadata.(map[string]any)["tier"] != "gold" ||
		res.Key.RequestCount != 1 || res.Key.LastRequest == nil {
		raw, _ := json.Marshal(res)
		t.Fatalf("result = %s", raw)
	}
	raw, _ := json.Marshal(res)
	var shape map[string]json.RawMessage
	_ = json.Unmarshal(raw, &shape)
	if _, hasKey := shape["key"]; !hasKey || rawKeys(t, shape["key"]) == "" {
		t.Fatalf("shape = %s", raw)
	}
	var inner map[string]any
	_ = json.Unmarshal(shape["key"], &inner)
	if _, leaked := inner["key"]; leaked {
		t.Fatal("verify must not return the key value")
	}
	// Step 2: unknown key
	expectInvalid(t, h.verify(t, "nope", nil), "INVALID_API_KEY", "Invalid API key.")
	// Step 3: disabled key (update over HTTP)
	expectOK(t, h.Post(t, "/api/auth/api-key/update", map[string]any{"keyId": k.ID, "enabled": false}, u.as()), nil)
	expectInvalid(t, h.verify(t, k.Key, nil), "KEY_DISABLED", "API Key is disabled")
}

func TestVerifyExpiry(t *testing.T) {
	h := newHarness(t)
	u := h.signUp(t)
	k := h.createKey(t, u, map[string]any{"expiresIn": 86400})
	if !h.verify(t, k.Key, nil).Valid {
		t.Fatal("fresh key should verify")
	}
	// Step 1: after expiry: KEY_EXPIRED and the key is deleted
	h.clock.Advance(86400*time.Second + time.Second)
	expectInvalid(t, h.verify(t, k.Key, nil), "KEY_EXPIRED", "API Key has expired")
	expectInvalid(t, h.verify(t, k.Key, nil), "INVALID_API_KEY", "Invalid API key.")
	expectError(t, h.Get(t, "/api/auth/api-key/get?id="+k.ID, u.as()), http.StatusNotFound, "KEY_NOT_FOUND", "API Key not found")
}

func TestVerifyPermissions(t *testing.T) {
	h := newHarness(t)
	u := h.signUp(t)
	k := h.serverKey(t, apikey.CreateAPIKeyInput{UserID: &u.ID, Permissions: map[string][]string{"files": {"read", "write"}, "users": {"read"}}})
	plain := h.serverKey(t, apikey.CreateAPIKeyInput{UserID: &u.ID})
	// Step 1: granted
	for _, p := range []map[string][]string{{"files": {"read"}}, {"files": {"read", "write"}, "users": {"read"}}} {
		if !h.verify(t, k.Key, p).Valid {
			t.Fatalf("permissions %v should be granted", p)
		}
	}
	// Step 2: denied: KEY_NOT_FOUND (better-auth's code for a permission mismatch)
	for _, p := range []map[string][]string{{"files": {"delete"}}, {"billing": {"read"}}, {"files": {"read"}, "users": {"write"}}, {}} {
		expectInvalid(t, h.verify(t, k.Key, p), "KEY_NOT_FOUND", "API Key not found")
	}
	// Step 3: a key without permissions never satisfies a permission check
	expectInvalid(t, h.verify(t, plain.Key, map[string][]string{"files": {"read"}}), "KEY_NOT_FOUND", "API Key not found")
	if !h.verify(t, plain.Key, nil).Valid {
		t.Fatal("no permissions requested: valid")
	}
}

func TestVerifyRemainingAndRefill(t *testing.T) {
	h := newHarness(t)
	u := h.signUp(t)
	// Step 1: remaining without refill: counts down, then the key is used up and deleted
	k := h.serverKey(t, apikey.CreateAPIKeyInput{UserID: &u.ID, Remaining: ptr[int64](2), RateLimitEnabled: ptr(false)})
	if r := h.verify(t, k.Key, nil); !r.Valid || *r.Key.Remaining != 1 {
		t.Fatalf("first = %+v", r.Key)
	}
	if r := h.verify(t, k.Key, nil); !r.Valid || *r.Key.Remaining != 0 {
		t.Fatalf("second = %+v", r.Key)
	}
	expectInvalid(t, h.verify(t, k.Key, nil), "USAGE_EXCEEDED", "API Key has reached its usage limit")
	expectInvalid(t, h.verify(t, k.Key, nil), "INVALID_API_KEY", "Invalid API key.")

	// Step 2: with refill: exhausted until refillInterval has passed since creation / the last refill
	r := h.serverKey(t, apikey.CreateAPIKeyInput{UserID: &u.ID, Remaining: ptr[int64](1), RefillAmount: ptr[int64](3),
		RefillInterval: ptr[int64](60_000), RateLimitEnabled: ptr(false)})
	if v := h.verify(t, r.Key, nil); !v.Valid || *v.Key.Remaining != 0 {
		t.Fatalf("use = %+v", v.Key)
	}
	expectInvalid(t, h.verify(t, r.Key, nil), "USAGE_EXCEEDED", "API Key has reached its usage limit")
	h.clock.Advance(30 * time.Second)
	expectInvalid(t, h.verify(t, r.Key, nil), "USAGE_EXCEEDED", "API Key has reached its usage limit")
	h.clock.Advance(31 * time.Second)
	v := h.verify(t, r.Key, nil)
	if !v.Valid || *v.Key.Remaining != 2 || v.Key.LastRefillAt == nil {
		t.Fatalf("after refill = %+v", v.Key)
	}
	refilledAt := time.Time(*v.Key.LastRefillAt)
	if !refilledAt.Equal(h.clock.Now()) {
		t.Fatalf("lastRefillAt = %v, want %v", refilledAt, h.clock.Now())
	}
	// the next refill is counted from lastRefillAt
	h.verify(t, r.Key, nil)
	h.verify(t, r.Key, nil)
	expectInvalid(t, h.verify(t, r.Key, nil), "USAGE_EXCEEDED", "API Key has reached its usage limit")
	h.clock.Advance(61 * time.Second)
	if v := h.verify(t, r.Key, nil); !v.Valid || *v.Key.Remaining != 2 {
		t.Fatalf("second refill = %+v", v.Key)
	}
	// the exhausted key with refill is kept (not deleted)
	if _, err := h.plugin.GetAPIKey(context.Background(), r.ID, "", u.ID); err != nil {
		t.Fatalf("refillable key deleted: %v", err)
	}
}

func TestVerifyRateLimitWindow(t *testing.T) {
	h := newHarness(t)
	u := h.signUp(t)
	k := h.serverKey(t, apikey.CreateAPIKeyInput{UserID: &u.ID, RateLimitMax: ptr[int64](2), RateLimitTimeWindow: ptr[int64](10_000)})
	// Step 1: two requests per window
	h.verify(t, k.Key, nil)
	h.clock.Advance(time.Second)
	if r := h.verify(t, k.Key, nil); !r.Valid || r.Key.RequestCount != 2 {
		t.Fatalf("second = %+v", r.Key)
	}
	// Step 2: the third is refused with RATE_LIMITED and tryAgainIn (ms left in the window)
	h.clock.Advance(time.Second)
	res := h.verify(t, k.Key, nil)
	if res.Valid || res.Error.Code != "RATE_LIMITED" || res.Error.Message != "Rate limit exceeded." {
		t.Fatalf("third = %+v", res.Error)
	}
	if got := res.Error.Details["tryAgainIn"]; got != int64(9000) {
		t.Fatalf("tryAgainIn = %#v, want 9000", got)
	}
	// Step 3: after the window the count restarts
	h.clock.Advance(9001 * time.Millisecond)
	if r := h.verify(t, k.Key, nil); !r.Valid || r.Key.RequestCount != 1 {
		t.Fatalf("new window = %+v", r.Key)
	}
	// Step 4: keys with rate limiting off are never limited
	free := h.serverKey(t, apikey.CreateAPIKeyInput{UserID: &u.ID, RateLimitEnabled: ptr(false), RateLimitMax: ptr[int64](1)})
	for i := 0; i < 5; i++ {
		if !h.verify(t, free.Key, nil).Valid {
			t.Fatalf("request %d limited", i)
		}
	}
}

func TestVerifyRateLimitDisabledByConfig(t *testing.T) {
	off := false
	h := newHarness(t, withConfigs(apikeyconfig.Configuration{RateLimit: apikeyconfig.RateLimit{Enabled: &off, MaxRequests: ptr(1)}}))
	u := h.signUp(t)
	k := h.serverKey(t, apikey.CreateAPIKeyInput{UserID: &u.ID, RateLimitEnabled: ptr(true)})
	for i := 0; i < 4; i++ {
		r := h.verify(t, k.Key, nil)
		if !r.Valid || r.Key.LastRequest == nil {
			t.Fatalf("request %d = %+v", i, r)
		}
	}
}

// TestVerifyConcurrent checks concurrent verifications of one key never fail with internal errors.
func TestVerifyConcurrent(t *testing.T) {
	h := newHarness(t)
	u := h.signUp(t)
	k := h.serverKey(t, apikey.CreateAPIKeyInput{UserID: &u.ID, RateLimitEnabled: ptr(false)})
	var wg sync.WaitGroup
	errs := make(chan string, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := h.plugin.VerifyAPIKey(context.Background(), apikey.VerifyAPIKeyInput{Key: k.Key})
			if err != nil || !res.Valid {
				errs <- "invalid"
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}

func TestVerifyCustomValidatorAndConfigScope(t *testing.T) {
	allow := true
	h := newHarness(t, withConfigs(
		apikeyconfig.Configuration{ConfigID: "default"},
		apikeyconfig.Configuration{ConfigID: "partner", DefaultPrefix: "pt_", CustomAPIKeyValidator: func(_ context.Context, key string) (bool, error) {
			return allow, nil
		}},
	))
	u := h.signUp(t)
	def := h.serverKey(t, apikey.CreateAPIKeyInput{UserID: &u.ID})
	partner := h.serverKey(t, apikey.CreateAPIKeyInput{UserID: &u.ID, ConfigID: "partner"})
	if partner.ConfigID != "partner" || def.ConfigID != "default" {
		t.Fatalf("configIds = %s %s", def.ConfigID, partner.ConfigID)
	}
	ctx := context.Background()
	// Step 1: unscoped verification uses the key's own configuration (and its validator)
	if !h.verify(t, partner.Key, nil).Valid {
		t.Fatal("partner key should verify")
	}
	allow = false
	expectInvalid(t, h.verify(t, partner.Key, nil), "KEY_NOT_FOUND", "API Key not found")
	// Step 2: scoped to the configuration: its validator runs first and answers like better-auth
	scope := "partner"
	res, err := h.plugin.VerifyAPIKey(ctx, apikey.VerifyAPIKeyInput{Key: partner.Key, ConfigID: &scope})
	if err != nil {
		t.Fatal(err)
	}
	expectInvalid(t, res, "KEY_NOT_FOUND", "Invalid API key.")
	allow = true
	// Step 3: a key of another configuration is not valid in this scope
	res, _ = h.plugin.VerifyAPIKey(ctx, apikey.VerifyAPIKeyInput{Key: def.Key, ConfigID: &scope})
	expectInvalid(t, res, "INVALID_API_KEY", "Invalid API key.")
	res, _ = h.plugin.VerifyAPIKey(ctx, apikey.VerifyAPIKeyInput{Key: partner.Key, ConfigID: &scope})
	if !res.Valid {
		t.Fatalf("scoped = %+v", res.Error)
	}
}

func TestDeferUpdates(t *testing.T) {
	var mu sync.Mutex
	var queued []func()
	h := newHarness(t,
		withConfigs(apikeyconfig.Configuration{DeferUpdates: true}),
		withAuthConfig(func(c *config.AuthConfig) {
			c.Advanced.BackgroundTasks.Handler = func(task func()) {
				mu.Lock()
				queued = append(queued, task)
				mu.Unlock()
			}
		}),
	)
	u := h.signUp(t)
	k := h.serverKey(t, apikey.CreateAPIKeyInput{UserID: &u.ID, Remaining: ptr[int64](3)})
	run := func() {
		mu.Lock()
		tasks := queued
		queued = nil
		mu.Unlock()
		for _, task := range tasks {
			task()
		}
	}
	// Step 1: the answer is optimistic; the database is written by the queued task
	res := h.verify(t, k.Key, nil)
	if !res.Valid || *res.Key.Remaining != 2 {
		t.Fatalf("optimistic = %+v", res.Key)
	}
	got, _ := h.plugin.GetAPIKey(context.Background(), k.ID, "", u.ID)
	if *got.Remaining != 3 {
		t.Fatalf("written before the task ran: %v", *got.Remaining)
	}
	run()
	got, _ = h.plugin.GetAPIKey(context.Background(), k.ID, "", u.ID)
	if *got.Remaining != 2 {
		t.Fatalf("after the task: %v", *got.Remaining)
	}
	// Step 2: an expired key is deleted by a queued task
	exp := h.serverKey(t, apikey.CreateAPIKeyInput{UserID: &u.ID, ExpiresIn: ptr(float64(86400))})
	h.clock.Advance(86401 * time.Second)
	expectInvalid(t, h.verify(t, exp.Key, nil), "KEY_EXPIRED", "API Key has expired")
	run()
	if n, _ := h.Auth.Adapter().Count(context.Background(), "apikey", []adapter.Where{{Field: "id", Value: exp.ID}}); n != 0 {
		t.Fatal("expired key not deleted by the background task")
	}
}

func TestDeleteAllExpired(t *testing.T) {
	h := newHarness(t)
	u := h.signUp(t)
	short := h.serverKey(t, apikey.CreateAPIKeyInput{UserID: &u.ID, ExpiresIn: ptr(float64(86400))})
	long := h.serverKey(t, apikey.CreateAPIKeyInput{UserID: &u.ID, ExpiresIn: ptr(float64(10 * 86400))})
	never := h.serverKey(t, apikey.CreateAPIKeyInput{UserID: &u.ID})
	h.clock.Advance(2 * 86400 * time.Second)
	if err := h.plugin.DeleteAllExpiredAPIKeys(context.Background()); err != nil {
		t.Fatal(err)
	}
	list, err := h.plugin.ListAPIKeys(context.Background(), u.ID, apikey.ListAPIKeysInput{})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, k := range list.APIKeys {
		ids[k.ID] = true
	}
	if ids[short.ID] || !ids[long.ID] || !ids[never.ID] || list.Total != 2 {
		t.Fatalf("left = %v", ids)
	}
	// the endpoint is server-only (no route), like better-auth 1.6.16
	if r := h.Post(t, "/api/auth/api-key/delete-all-expired-api-keys", map[string]any{}, u.as()); r.Status != http.StatusNotFound && r.Status != http.StatusMethodNotAllowed {
		t.Fatalf("route exists: %d", r.Status)
	}
	if r := h.Post(t, "/api/auth/api-key/verify", map[string]any{"key": never.Key}, u.as()); r.Status != http.StatusNotFound && r.Status != http.StatusMethodNotAllowed {
		t.Fatalf("verify route exists: %d", r.Status)
	}
}
