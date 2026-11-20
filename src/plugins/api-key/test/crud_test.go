package test

import (
	"context"

	"fmt"
	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/config"
	"net/http"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/plugins/admin"
	apikey "github.com/better-go-auth/goauth/src/plugins/api-key"
	apikeyconfig "github.com/better-go-auth/goauth/src/plugins/api-key/config"
)

func TestGetKey(t *testing.T) {
	h := newHarness(t)
	alice, bob := h.signUp(t), h.signUp(t)
	k := h.createKey(t, alice, map[string]any{"name": "a"})
	// Step 1: the owner reads it (no key value)
	r := h.Get(t, "/api/auth/api-key/get?id="+k.ID, alice.as())
	var got keyBody
	expectOK(t, r, &got)
	if got.ID != k.ID || got.Key != "" || *got.Name != "a" {
		t.Fatalf("get = %+v", got)
	}
	want := "configId,createdAt,enabled,expiresAt,id,lastRefillAt,lastRequest,metadata,name,permissions,prefix," +
		"rateLimitEnabled,rateLimitMax,rateLimitTimeWindow,referenceId,refillAmount,refillInterval,remaining,requestCount,start,updatedAt"
	if keys := rawKeys(t, r.Body); keys != want {
		t.Fatalf("keys = %s", keys)
	}
	// Step 2: another user, an unknown id, no session, missing id
	expectError(t, h.Get(t, "/api/auth/api-key/get?id="+k.ID, bob.as()), http.StatusNotFound, "KEY_NOT_FOUND")
	expectError(t, h.Get(t, "/api/auth/api-key/get?id=missing", alice.as()), http.StatusNotFound, "KEY_NOT_FOUND")
	expectError(t, h.Get(t, "/api/auth/api-key/get?id="+k.ID), http.StatusUnauthorized, "UNAUTHORIZED")
	expectError(t, h.Get(t, "/api/auth/api-key/get"), http.StatusBadRequest, "VALIDATION_ERROR")
}

func TestUpdateKey(t *testing.T) {
	h := newHarness(t, withConfigs(apikeyconfig.Configuration{EnableMetadata: true, MaximumNameLength: 10}))
	alice, bob := h.signUp(t), h.signUp(t)
	k := h.createKey(t, alice, map[string]any{"name": "a"})
	post := func(u user, body map[string]any) *keyBody {
		body["keyId"] = k.ID
		var out keyBody
		expectOK(t, h.Post(t, "/api/auth/api-key/update", body, u.as()), &out)
		return &out
	}
	// Step 1: client-settable fields
	got := post(alice, map[string]any{"name": "renamed", "enabled": false, "metadata": map[string]any{"x": 1}, "expiresIn": 3 * 86400})
	if *got.Name != "renamed" || got.Enabled || got.Metadata.(map[string]any)["x"] != float64(1) || got.ExpiresAt == nil || got.Key != "" {
		t.Fatalf("update = %+v", got)
	}
	// expiresIn null removes the expiry; metadata null clears it
	got = post(alice, map[string]any{"expiresIn": nil, "metadata": nil})
	if got.ExpiresAt != nil || got.Metadata != nil {
		t.Fatalf("cleared = %+v", got)
	}
	// Step 2: errors
	cases := []struct {
		name   string
		u      *user
		body   map[string]any
		status int
		code   string
	}{
		{"no session", nil, map[string]any{"name": "x"}, 401, "UNAUTHORIZED_SESSION"},
		{"not owner", &bob, map[string]any{"name": "x"}, 404, "KEY_NOT_FOUND"},
		{"unknown key", &alice, map[string]any{"keyId": "nope", "name": "x"}, 404, "KEY_NOT_FOUND"},
		{"nothing to update", &alice, map[string]any{}, 400, "NO_VALUES_TO_UPDATE"},
		{"name too long", &alice, map[string]any{"name": "abcdefghijk"}, 400, "INVALID_NAME_LENGTH"},
		{"empty name", &alice, map[string]any{"name": ""}, 400, "INVALID_NAME_LENGTH"},
		{"server only remaining", &alice, map[string]any{"remaining": 3}, 400, "SERVER_ONLY_PROPERTY"},
		{"server only permissions", &alice, map[string]any{"permissions": nil}, 400, "SERVER_ONLY_PROPERTY"},
		{"server only rate limit", &alice, map[string]any{"rateLimitMax": 3}, 400, "SERVER_ONLY_PROPERTY"},
		{"server only refill", &alice, map[string]any{"refillAmount": 3, "refillInterval": 100}, 400, "SERVER_ONLY_PROPERTY"},
		{"other userId", &alice, map[string]any{"userId": bob.ID, "name": "x"}, 401, "UNAUTHORIZED_SESSION"},
		{"expiresIn too small", &alice, map[string]any{"expiresIn": 60}, 400, "EXPIRES_IN_IS_TOO_SMALL"},
		{"expiresIn too large", &alice, map[string]any{"expiresIn": 400 * 86400}, 400, "EXPIRES_IN_IS_TOO_LARGE"},
		{"metadata type", &alice, map[string]any{"metadata": "x"}, 400, "INVALID_METADATA_TYPE"},
		{"missing keyId", &alice, map[string]any{"keyId": nil, "name": "x"}, 400, "VALIDATION_ERROR"},
		{"remaining below 1", &alice, map[string]any{"remaining": 0}, 400, "VALIDATION_ERROR"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, set := c.body["keyId"]; !set {
				c.body["keyId"] = k.ID
			}
			if c.body["keyId"] == nil {
				delete(c.body, "keyId")
			}
			headers := map[string]string{}
			if c.u != nil {
				headers = c.u.as()
			}
			expectError(t, h.Post(t, "/api/auth/api-key/update", c.body, headers), c.status, c.code)
		})
	}
	// the own userId is accepted
	post(alice, map[string]any{"userId": alice.ID, "enabled": true})

	// Step 3: server-side updates may set server-only fields
	ctx := context.Background()
	perms := map[string][]string{"files": {"read"}}
	upd, err := h.plugin.UpdateAPIKey(ctx, apikey.UpdateAPIKeyInput{KeyID: k.ID, UserID: &alice.ID, Remaining: ptr[int64](9),
		RefillAmount: ptr[int64](9), RefillInterval: ptr[int64](1000), RateLimitMax: ptr[int64](4), RateLimitTimeWindow: ptr[int64](500),
		RateLimitEnabled: ptr(false), Permissions: apikey.Value(perms)})
	if err != nil {
		t.Fatal(err)
	}
	if *upd.Remaining != 9 || *upd.RefillAmount != 9 || *upd.RefillInterval != 1000 || *upd.RateLimitMax != 4 ||
		*upd.RateLimitTimeWindow != 500 || upd.RateLimitEnabled || upd.Permissions["files"][0] != "read" {
		t.Fatalf("server update = %+v", upd)
	}
	upd, err = h.plugin.UpdateAPIKey(ctx, apikey.UpdateAPIKeyInput{KeyID: k.ID, UserID: &alice.ID, Permissions: apikey.Null[map[string][]string]()})
	if err != nil || upd.Permissions != nil {
		t.Fatalf("permissions cleared = %+v, %v", upd, err)
	}
	_, err = h.plugin.UpdateAPIKey(ctx, apikey.UpdateAPIKeyInput{KeyID: k.ID, UserID: &alice.ID, RefillAmount: ptr[int64](1)})
	expectAuthErr(t, err, 400, "REFILL_AMOUNT_AND_INTERVAL_REQUIRED")
	_, err = h.plugin.UpdateAPIKey(ctx, apikey.UpdateAPIKeyInput{KeyID: k.ID, UserID: &alice.ID, RefillInterval: ptr[int64](1)})
	expectAuthErr(t, err, 400, "REFILL_INTERVAL_AND_AMOUNT_REQUIRED")
	_, err = h.plugin.UpdateAPIKey(ctx, apikey.UpdateAPIKeyInput{KeyID: k.ID, Name: ptr("x")})
	expectAuthErr(t, err, 401, "UNAUTHORIZED_SESSION")
	_, err = h.plugin.UpdateAPIKey(ctx, apikey.UpdateAPIKeyInput{KeyID: k.ID, UserID: &bob.ID, Name: ptr("x")})
	expectAuthErr(t, err, 404, "KEY_NOT_FOUND")
}

func TestUpdateMetadataDisabledIsIgnored(t *testing.T) {
	h := newHarness(t)
	u := h.signUp(t)
	k := h.createKey(t, u, nil)
	// metadata is silently dropped without EnableMetadata (better-auth), so nothing is left to update
	expectError(t, h.Post(t, "/api/auth/api-key/update", map[string]any{"keyId": k.ID, "metadata": map[string]any{"a": 1}}, u.as()),
		400, "NO_VALUES_TO_UPDATE", "No values to update.")
	expectOK(t, h.Post(t, "/api/auth/api-key/update", map[string]any{"keyId": k.ID, "expiresIn": 86400}, u.as()), nil)
}

func TestDeleteKey(t *testing.T) {
	h := newHarness(t, withServer(func(o *goauth.GoAuthOptions) {
		p, err := admin.NewWithGorm(o.Conn)
		if err != nil {
			t.Fatal(err)
		}
		o.Plugins = append(o.Plugins, p)
	}))
	alice, bob := h.signUp(t), h.signUp(t)
	k := h.createKey(t, alice, nil)
	// Step 1: errors
	expectError(t, h.Post(t, "/api/auth/api-key/delete", map[string]any{"keyId": k.ID}), 401, "UNAUTHORIZED")
	expectError(t, h.Post(t, "/api/auth/api-key/delete", map[string]any{}, alice.as()), 400, "VALIDATION_ERROR")
	expectError(t, h.Post(t, "/api/auth/api-key/delete", map[string]any{"keyId": k.ID}, bob.as()), 404, "KEY_NOT_FOUND")
	expectError(t, h.Post(t, "/api/auth/api-key/delete", map[string]any{"keyId": "nope"}, alice.as()), 404, "KEY_NOT_FOUND")
	// Step 2: the owner deletes it
	var ok struct {
		Success bool `json:"success"`
	}
	expectOK(t, h.Post(t, "/api/auth/api-key/delete", map[string]any{"keyId": k.ID}, alice.as()), &ok)
	if !ok.Success {
		t.Fatal("success = false")
	}
	expectInvalid(t, h.verify(t, k.Key, nil), "INVALID_API_KEY", "Invalid API key.")
	// Step 3: banned users cannot delete keys (Go API reads the user)
	k2 := h.createKey(t, alice, nil)
	if _, err := h.Auth.Adapter().Update(context.Background(), "user", []adapter.Where{{Field: "id", Value: alice.ID}},
		adapter.Record{"banned": true}); err != nil {
		t.Fatal(err)
	}
	expectAuthErr(t, h.plugin.DeleteAPIKey(context.Background(), k2.ID, "", alice.ID), 401, "USER_BANNED")
}

func TestListKeys(t *testing.T) {
	h := newHarness(t)
	alice, bob := h.signUp(t), h.signUp(t)
	var ids []string
	for i := 0; i < 5; i++ {
		k := h.createKey(t, alice, map[string]any{"name": fmt.Sprintf("key-%d", 4-i)})
		ids = append(ids, k.ID)
		h.clock.Advance(time.Second)
	}
	h.createKey(t, bob, nil)
	type listBody struct {
		APIKeys []keyBody `json:"apiKeys"`
		Total   int       `json:"total"`
		Limit   *int      `json:"limit"`
		Offset  *int      `json:"offset"`
	}
	// Step 1: all of alice's keys, no key values, no limit/offset in the body
	r := h.Get(t, "/api/auth/api-key/list", alice.as())
	var all listBody
	expectOK(t, r, &all)
	if all.Total != 5 || len(all.APIKeys) != 5 || all.Limit != nil || all.Offset != nil || rawKeys(t, r.Body) != "apiKeys,total" {
		t.Fatalf("list = %s", r.Body)
	}
	for _, k := range all.APIKeys {
		if k.Key != "" || k.ReferenceID != alice.ID {
			t.Fatalf("listed key = %+v", k)
		}
	}
	// Step 2: sorted and paginated (total counts every key)
	var page listBody
	expectOK(t, h.Get(t, "/api/auth/api-key/list?sortBy=name&sortDirection=asc&limit=2&offset=1", alice.as()), &page)
	if page.Total != 5 || len(page.APIKeys) != 2 || *page.APIKeys[0].Name != "key-1" || *page.APIKeys[1].Name != "key-2" ||
		*page.Limit != 2 || *page.Offset != 1 {
		t.Fatalf("page = %+v", page)
	}
	expectOK(t, h.Get(t, "/api/auth/api-key/list?sortBy=createdAt&sortDirection=desc&limit=1", alice.as()), &page)
	if page.APIKeys[0].ID != ids[4] {
		t.Fatalf("newest = %s, want %s", page.APIKeys[0].ID, ids[4])
	}
	// Step 3: query validation and authentication
	expectError(t, h.Get(t, "/api/auth/api-key/list?limit=-1", alice.as()), 400, "VALIDATION_ERROR")
	expectError(t, h.Get(t, "/api/auth/api-key/list?limit=abc", alice.as()), 400, "VALIDATION_ERROR")
	expectError(t, h.Get(t, "/api/auth/api-key/list?sortDirection=up", alice.as()), 400, "VALIDATION_ERROR")
	expectError(t, h.Get(t, "/api/auth/api-key/list"), 401, "UNAUTHORIZED")
	// Step 4: a user without keys
	carol := h.signUp(t)
	var empty listBody
	expectOK(t, h.Get(t, "/api/auth/api-key/list", carol.as()), &empty)
	if empty.Total != 0 || empty.APIKeys == nil || len(empty.APIKeys) != 0 {
		t.Fatalf("empty = %+v", empty)
	}
}

func TestMultipleConfigurations(t *testing.T) {
	h := newHarness(t, withConfigs(
		apikeyconfig.Configuration{ConfigID: "default"},
		apikeyconfig.Configuration{ConfigID: "readonly", DefaultPrefix: "ro_", RateLimit: apikeyconfig.RateLimit{MaxRequests: ptr(100)}},
	))
	u := h.signUp(t)
	def := h.createKey(t, u, nil)
	ro := h.createKey(t, u, map[string]any{"configId": "readonly"})
	if ro.ConfigID != "readonly" || *ro.Prefix != "ro_" || *ro.RateLimitMax != 100 || def.ConfigID != "default" {
		t.Fatalf("keys = %+v / %+v", def, ro)
	}
	// Step 1: lookups are scoped to the configuration
	expectError(t, h.Get(t, "/api/auth/api-key/get?id="+ro.ID, u.as()), 404, "KEY_NOT_FOUND")
	expectOK(t, h.Get(t, "/api/auth/api-key/get?id="+ro.ID+"&configId=readonly", u.as()), nil)
	// Step 2: list everything or one configuration
	var all, one struct {
		Total int `json:"total"`
	}
	expectOK(t, h.Get(t, "/api/auth/api-key/list", u.as()), &all)
	expectOK(t, h.Get(t, "/api/auth/api-key/list?configId=readonly", u.as()), &one)
	if all.Total != 2 || one.Total != 1 {
		t.Fatalf("totals = %d / %d", all.Total, one.Total)
	}
	// Step 3: without a default configuration a request without configId fails
	h2 := newHarness(t, withConfigs(apikeyconfig.Configuration{ConfigID: "a"}, apikeyconfig.Configuration{ConfigID: "b"}))
	u2 := h2.signUp(t)
	expectError(t, h2.Post(t, "/api/auth/api-key/create", map[string]any{}, u2.as()), 400, "NO_DEFAULT_API_KEY_CONFIGURATION_FOUND",
		"No default api-key configuration found.")
	h2.createKey(t, u2, map[string]any{"configId": "b"})
	// Step 4: invalid configuration lists are rejected
	if _, err := apikey.NewWithConfigurations([]apikeyconfig.Configuration{{ConfigID: "a"}, {ConfigID: "a"}}); err == nil {
		t.Fatal("duplicate configId accepted")
	}
}

// TestDisabledRoutes checks AuthConfig.DisabledOps applies to the plugin's operations.
func TestDisabledRoutes(t *testing.T) {
	h := newHarness(t, withAuthConfig(func(c *config.AuthConfig) { c.DisabledOps = append(c.DisabledOps, "listApiKeys") }))
	u := h.signUp(t)
	if r := h.Get(t, "/api/auth/api-key/list", u.as()); r.Status != http.StatusNotFound {
		t.Fatalf("disabled list: %d", r.Status)
	}
}
