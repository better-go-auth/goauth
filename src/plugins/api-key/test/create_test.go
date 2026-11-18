package test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	apikey "github.com/better-go-auth/goauth/src/plugins/api-key"
	apikeyconfig "github.com/better-go-auth/goauth/src/plugins/api-key/config"
	"github.com/better-go-auth/goauth/src/providers/access"
)

// TestCreateDefaults checks a key created over HTTP with better-auth's defaults: shape, stored hash,
// start, rate-limit defaults, no expiry, no permissions.
func TestCreateDefaults(t *testing.T) {
	h := newHarness(t)
	u := h.signUp(t)
	r := h.Post(t, "/api/auth/api-key/create", map[string]any{"name": "my key"}, u.as())
	var k keyBody
	expectOK(t, r, &k)
	// Step 1: the response has every field of better-auth's ApiKey plus the plain key
	want := "configId,createdAt,enabled,expiresAt,id,key,lastRefillAt,lastRequest,metadata,name,permissions,prefix," +
		"rateLimitEnabled,rateLimitMax,rateLimitTimeWindow,referenceId,refillAmount,refillInterval,remaining,requestCount,start,updatedAt"
	if got := rawKeys(t, r.Body); got != want {
		t.Fatalf("keys = %s\nwant   %s", got, want)
	}
	// Step 2: values
	if len(k.Key) != 64 || strings.Trim(k.Key, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
		t.Fatalf("key = %q (64 letters expected)", k.Key)
	}
	if k.ConfigID != "default" || k.ReferenceID != u.ID || *k.Name != "my key" || *k.Start != k.Key[:6] || k.Prefix != nil ||
		!k.Enabled || !k.RateLimitEnabled || *k.RateLimitTimeWindow != 86400000 || *k.RateLimitMax != 10 ||
		k.RequestCount != 0 || k.Remaining != nil || k.ExpiresAt != nil || k.Permissions != nil || k.Metadata != nil {
		t.Fatalf("key = %+v", k)
	}
	// Step 3: the database keeps the SHA-256 hash, never the key
	stored := storedKeyColumn(t, h, k.ID)
	if stored != apikey.HashKey(k.Key) || stored == k.Key {
		t.Fatalf("stored key = %q, want the hash", stored)
	}
}

// storedKeyColumn reads the key column of a row through the adapter.
func storedKeyColumn(t *testing.T, h *harness, id string) string {
	t.Helper()
	rec, err := h.Auth.Adapter().FindOne(context.Background(), "apikey", []adapter.Where{{Field: "id", Value: id}})
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	return rec["key"].(string)
}

func TestCreateClientRules(t *testing.T) {
	h := newHarness(t)
	u := h.signUp(t)
	// Step 1: no session → 401 UNAUTHORIZED_SESSION
	expectError(t, h.Post(t, "/api/auth/api-key/create", map[string]any{}), http.StatusUnauthorized, "UNAUTHORIZED_SESSION",
		"Unauthorized or invalid session")
	// Step 2: server-only properties → 400 SERVER_ONLY_PROPERTY
	for _, body := range []map[string]any{
		{"remaining": 5}, {"refillAmount": 5, "refillInterval": 1000}, {"refillInterval": 1000}, {"rateLimitMax": 3},
		{"rateLimitTimeWindow": 100}, {"rateLimitEnabled": false}, {"permissions": map[string]any{"files": []string{"read"}}},
		{"permissions": map[string]any{}},
	} {
		expectError(t, h.Post(t, "/api/auth/api-key/create", body, u.as()), http.StatusBadRequest, "SERVER_ONLY_PROPERTY",
			"The property you're trying to set can only be set from the server auth instance only.")
	}
	// remaining: null is the default, not a server-only value
	h.createKey(t, u, map[string]any{"remaining": nil})
	// Step 3: userId from a client → 401 UNAUTHORIZED_SESSION (even its own)
	expectError(t, h.Post(t, "/api/auth/api-key/create", map[string]any{"userId": u.ID}, u.as()), http.StatusUnauthorized, "UNAUTHORIZED_SESSION")
}

func TestCreateValidation(t *testing.T) {
	h := newHarness(t, withConfigs(apikeyconfig.Configuration{MaximumNameLength: 5, MaximumPrefixLength: 4, MinimumPrefixLength: 2}))
	u := h.signUp(t)
	cases := []struct {
		name   string
		body   map[string]any
		status int
		code   string
	}{
		{"prefix format", map[string]any{"prefix": "bad prefix!"}, 400, "VALIDATION_ERROR"},
		{"prefix too short", map[string]any{"prefix": "a"}, 400, "INVALID_PREFIX_LENGTH"},
		{"prefix too long", map[string]any{"prefix": "abcde"}, 400, "INVALID_PREFIX_LENGTH"},
		{"name too long", map[string]any{"name": "abcdef"}, 400, "INVALID_NAME_LENGTH"},
		{"expiresIn too small (zod)", map[string]any{"expiresIn": 0}, 400, "VALIDATION_ERROR"},
		{"expiresIn below one day", map[string]any{"expiresIn": 3600}, 400, "EXPIRES_IN_IS_TOO_SMALL"},
		{"expiresIn above a year", map[string]any{"expiresIn": 366 * 86400}, 400, "EXPIRES_IN_IS_TOO_LARGE"},
		{"metadata disabled", map[string]any{"metadata": map[string]any{"a": 1}}, 400, "METADATA_DISABLED"},
		{"name wrong type", map[string]any{"name": 12}, 400, "VALIDATION_ERROR"},
		{"remaining negative", map[string]any{"remaining": -1}, 400, "VALIDATION_ERROR"},
		{"prefix null", map[string]any{"prefix": nil}, 400, "VALIDATION_ERROR"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			expectError(t, h.Post(t, "/api/auth/api-key/create", c.body, u.as()), c.status, c.code)
		})
	}
	// Step 2: the prefix message is better-auth's zod message
	e := expectError(t, h.Post(t, "/api/auth/api-key/create", map[string]any{"prefix": "a b"}, u.as()), 400, "VALIDATION_ERROR")
	if !strings.Contains(e.Message, "Invalid prefix format, must be alphanumeric and contain only underscores and hyphens.") {
		t.Fatalf("message = %q", e.Message)
	}
	// Step 3: a valid prefix and expiry are applied
	k := h.createKey(t, u, map[string]any{"prefix": "gk_", "expiresIn": 2 * 86400, "name": "ok"})
	if !strings.HasPrefix(k.Key, "gk_") || *k.Prefix != "gk_" || *k.Start != k.Key[:6] || k.ExpiresAt == nil {
		t.Fatalf("key = %+v", k)
	}
	if d := k.ExpiresAt.Sub(h.clock.Now()); d < 47*time.Hour || d > 49*time.Hour {
		t.Fatalf("expiresAt in %v", d)
	}
}

func TestCreateOptions(t *testing.T) {
	// Step 1: requireName, metadata, default prefix, starting characters, default expiry
	no := false
	h := newHarness(t, withConfigs(apikeyconfig.Configuration{
		RequireName: true, EnableMetadata: true, DefaultPrefix: "app_", DefaultKeyLength: 20,
		StartingCharactersConfig: apikeyconfig.StartingCharacters{CharactersLength: 8},
		KeyExpiration:            apikeyconfig.KeyExpiration{DefaultExpiresIn: 2 * time.Hour},
		RateLimit:                apikeyconfig.RateLimit{Enabled: &no, TimeWindow: time.Minute, MaxRequests: ptr(3)},
	}))
	u := h.signUp(t)
	expectError(t, h.Post(t, "/api/auth/api-key/create", map[string]any{}, u.as()), 400, "NAME_REQUIRED", "API Key name is required.")
	expectError(t, h.Post(t, "/api/auth/api-key/create", map[string]any{"name": ""}, u.as()), 400, "NAME_REQUIRED")
	expectError(t, h.Post(t, "/api/auth/api-key/create", map[string]any{"name": "x", "metadata": "text"}, u.as()), 400, "INVALID_METADATA_TYPE",
		"metadata must be an object or undefined")
	k := h.createKey(t, u, map[string]any{"name": "x", "metadata": map[string]any{"plan": "pro", "seats": 3}})
	if !strings.HasPrefix(k.Key, "app_") || len(k.Key) != 24 || *k.Prefix != "app_" || *k.Start != k.Key[:8] {
		t.Fatalf("key = %+v", k)
	}
	if md := k.Metadata.(map[string]any); md["plan"] != "pro" || md["seats"] != float64(3) {
		t.Fatalf("metadata = %#v", k.Metadata)
	}
	if k.ExpiresAt == nil || k.ExpiresAt.Sub(h.clock.Now()).Round(time.Minute) != 2*time.Hour {
		t.Fatalf("default expiry = %v", k.ExpiresAt)
	}
	if k.RateLimitEnabled || *k.RateLimitTimeWindow != 60000 || *k.RateLimitMax != 3 {
		t.Fatalf("rate limit = %+v", k)
	}
	// Step 2: metadata survives a read
	var got keyBody
	expectOK(t, h.Get(t, "/api/auth/api-key/get?id="+k.ID, u.as()), &got)
	if got.Metadata.(map[string]any)["plan"] != "pro" || got.Key != "" {
		t.Fatalf("get = %+v", got)
	}

	// Step 3: no start stored, custom expiry disabled, custom generator
	h2 := newHarness(t, withConfigs(apikeyconfig.Configuration{
		StartingCharactersConfig: apikeyconfig.StartingCharacters{ShouldStore: &no},
		KeyExpiration:            apikeyconfig.KeyExpiration{DisableCustomExpiresTime: true},
		CustomKeyGenerator: func(_ context.Context, length int, prefix string) (string, error) {
			return prefix + "custom-" + strings.Repeat("k", length), nil
		},
	}))
	u2 := h2.signUp(t)
	k2 := h2.createKey(t, u2, nil)
	if k2.Start != nil || k2.Key != "custom-"+strings.Repeat("k", 64) {
		t.Fatalf("key = %+v", k2)
	}
	expectError(t, h2.Post(t, "/api/auth/api-key/create", map[string]any{"expiresIn": 2 * 86400}, u2.as()), 400, "KEY_DISABLED_EXPIRATION",
		"Custom key expiration values are disabled.")
}

func TestCreateServerSide(t *testing.T) {
	h := newHarness(t, withConfigs(apikeyconfig.Configuration{
		Permissions: apikeyconfig.Permissions{DefaultPermissions: access.Statements{"files": {"read"}}},
	}))
	u := h.signUp(t)
	ctx := context.Background()
	// Step 1: server-only fields are allowed; remaining / refill / rate limit / permissions stored
	k, err := h.plugin.CreateAPIKey(ctx, apikey.CreateAPIKeyInput{
		UserID: &u.ID, Name: ptr("server"), Remaining: ptr[int64](5), RefillAmount: ptr[int64](5),
		RefillInterval: ptr[int64](60000), RateLimitMax: ptr[int64](2), RateLimitTimeWindow: ptr[int64](1000),
		RateLimitEnabled: ptr(true), Permissions: map[string][]string{"files": {"read", "write"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if k.ReferenceID != u.ID || *k.Remaining != 5 || *k.RefillAmount != 5 || *k.RefillInterval != 60000 ||
		*k.RateLimitMax != 2 || *k.RateLimitTimeWindow != 1000 || len(k.Permissions["files"]) != 2 {
		t.Fatalf("key = %+v", k)
	}
	// Step 2: default permissions apply when none are given
	k2, err := h.plugin.CreateAPIKey(ctx, apikey.CreateAPIKeyInput{UserID: &u.ID})
	if err != nil || k2.Permissions["files"][0] != "read" {
		t.Fatalf("default permissions = %+v, %v", k2, err)
	}
	// Step 3: owner rules and refill pairs
	_, err = h.plugin.CreateAPIKey(ctx, apikey.CreateAPIKeyInput{})
	expectAuthErr(t, err, http.StatusUnauthorized, "UNAUTHORIZED_SESSION")
	_, err = h.plugin.CreateAPIKey(ctx, apikey.CreateAPIKeyInput{UserID: &u.ID, RefillAmount: ptr[int64](5)})
	expectAuthErr(t, err, http.StatusBadRequest, "REFILL_AMOUNT_AND_INTERVAL_REQUIRED")
	_, err = h.plugin.CreateAPIKey(ctx, apikey.CreateAPIKeyInput{UserID: &u.ID, RefillInterval: ptr[int64](5)})
	expectAuthErr(t, err, http.StatusBadRequest, "REFILL_INTERVAL_AND_AMOUNT_REQUIRED")
	// Step 4: an unknown configId falls back to the default configuration
	k3, err := h.plugin.CreateAPIKey(ctx, apikey.CreateAPIKeyInput{UserID: &u.ID, ConfigID: "nope"})
	if err != nil || k3.ConfigID != "default" {
		t.Fatalf("fallback config = %+v, %v", k3, err)
	}
	// Step 5: default permissions computed per owner
	h2 := newHarness(t, withConfigs(apikeyconfig.Configuration{
		Permissions: apikeyconfig.Permissions{DefaultPermissionsFunc: func(_ context.Context, ref string) (access.Statements, error) {
			return access.Statements{"owner": {ref}}, nil
		}},
	}))
	u2 := h2.signUp(t)
	k4 := h2.createKey(t, u2, nil)
	if k4.Permissions["owner"][0] != u2.ID {
		t.Fatalf("permissions = %v", k4.Permissions)
	}
}

// expectAuthErr checks a Go API error's status and code.
func expectAuthErr(t *testing.T, err error, status int, code string) {
	t.Helper()
	var ae *autherr.AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("error = %v, want %s", err, code)
	}
	if ae.StatusCode != status || string(ae.Code) != code {
		t.Fatalf("error = %d %s, want %d %s", ae.StatusCode, ae.Code, status, code)
	}
}

func TestKeyHashingDisabled(t *testing.T) {
	h := newHarness(t, withConfigs(apikeyconfig.Configuration{DisableKeyHashing: true}))
	u := h.signUp(t)
	k := h.createKey(t, u, nil)
	if got := storedKeyColumn(t, h, k.ID); got != k.Key {
		t.Fatalf("stored = %q, want the plain key", got)
	}
	res, err := h.plugin.VerifyAPIKey(context.Background(), apikey.VerifyAPIKeyInput{Key: k.Key})
	if err != nil || !res.Valid {
		t.Fatalf("verify = %+v, %v", res, err)
	}
}
