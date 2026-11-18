package test

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	apikey "github.com/better-go-auth/goauth/src/plugins/api-key"
	apikeyconfig "github.com/better-go-auth/goauth/src/plugins/api-key/config"
	"github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

// storeValue reads a secondary-storage value as a string.
func storeValue(t *testing.T, store interface {
	Get(ctx context.Context, key string) (any, bool, error)
}, key string) (string, bool) {
	t.Helper()
	v, ok, err := store.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || v == nil {
		return "", false
	}
	s, _ := v.(string)
	return s, true
}

// dbCount counts the apikey rows of an owner.
func dbCount(t *testing.T, h *harness, ref string) int64 {
	t.Helper()
	n, err := h.Auth.Adapter().Count(context.Background(), "apikey", []adapter.Where{{Field: "referenceId", Value: ref}})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSecondaryStorageMode(t *testing.T) {
	store := memory.New()
	h := newHarness(t,
		withConfigs(apikeyconfig.Configuration{Storage: apikeyconfig.StorageSecondary, EnableSessionForAPIKeys: true, EnableMetadata: true}),
		withServer(compattest.WithSecondaryStorage(store)))
	u := h.signUp(t)
	k := h.createKey(t, u, map[string]any{"name": "cached", "expiresIn": 2 * 86400, "metadata": map[string]any{"a": "b"}})
	// Step 1: nothing in the database; better-auth's three storage keys
	if n := dbCount(t, h, u.ID); n != 0 {
		t.Fatalf("database rows = %d", n)
	}
	byHash, ok := storeValue(t, store, "api-key:"+apikey.HashKey(k.Key))
	if !ok {
		t.Fatal("api-key:<hash> missing")
	}
	var stored map[string]any
	if err := json.Unmarshal([]byte(byHash), &stored); err != nil {
		t.Fatal(err)
	}
	if stored["id"] != k.ID || stored["key"] != apikey.HashKey(k.Key) || stored["referenceId"] != u.ID ||
		stored["expiresAt"] == nil || stored["metadata"].(map[string]any)["a"] != "b" {
		t.Fatalf("stored = %s", byHash)
	}
	if byID, ok := storeValue(t, store, "api-key:by-id:"+k.ID); !ok || byID != byHash {
		t.Fatalf("by-id = %q", byID)
	}
	if ref, ok := storeValue(t, store, "api-key:by-ref:"+u.ID); !ok || ref != `["`+k.ID+`"]` {
		t.Fatalf("by-ref = %q", ref)
	}
	// Step 2: get / verify / session / update / list work from the storage
	var got keyBody
	expectOK(t, h.Get(t, "/api/auth/api-key/get?id="+k.ID, u.as()), &got)
	if *got.Name != "cached" {
		t.Fatalf("get = %+v", got)
	}
	if r := h.verify(t, k.Key, nil); !r.Valid || r.Key.RequestCount != 1 {
		t.Fatalf("verify = %+v", r)
	}
	expectOK(t, h.Get(t, "/api/auth/get-session", keyHeader(k.Key)), nil)
	var upd keyBody
	expectOK(t, h.Post(t, "/api/auth/api-key/update", map[string]any{"keyId": k.ID, "name": "renamed"}, u.as()), &upd)
	if *upd.Name != "renamed" || upd.RequestCount != 2 || !upd.UpdatedAt.After(got.UpdatedAt.Add(-time.Millisecond)) {
		t.Fatalf("update = %+v", upd)
	}
	k2 := h.createKey(t, u, map[string]any{"name": "second"})
	var list struct {
		APIKeys []keyBody `json:"apiKeys"`
		Total   int       `json:"total"`
	}
	expectOK(t, h.Get(t, "/api/auth/api-key/list?sortBy=name&sortDirection=desc", u.as()), &list)
	if list.Total != 2 || *list.APIKeys[0].Name != "second" || *list.APIKeys[1].Name != "renamed" {
		t.Fatalf("list = %+v", list)
	}
	// Step 3: delete removes the three keys' entries
	expectOK(t, h.Post(t, "/api/auth/api-key/delete", map[string]any{"keyId": k.ID}, u.as()), nil)
	if _, ok := storeValue(t, store, "api-key:"+apikey.HashKey(k.Key)); ok {
		t.Fatal("hash entry left")
	}
	if ref, _ := storeValue(t, store, "api-key:by-ref:"+u.ID); ref != `["`+k2.ID+`"]` {
		t.Fatalf("by-ref after delete = %q", ref)
	}
	expectOK(t, h.Post(t, "/api/auth/api-key/delete", map[string]any{"keyId": k2.ID}, u.as()), nil)
	if _, ok := storeValue(t, store, "api-key:by-ref:"+u.ID); ok {
		t.Fatal("empty by-ref list must be deleted")
	}
}

func TestSecondaryStorageWithFallback(t *testing.T) {
	store := memory.New()
	h := newHarness(t,
		withConfigs(apikeyconfig.Configuration{Storage: apikeyconfig.StorageSecondary, FallbackToDatabase: true}),
		withServer(compattest.WithSecondaryStorage(store)))
	u := h.signUp(t)
	k := h.createKey(t, u, nil)
	// Step 1: written to both; the owner list is not kept (it is a cache rebuilt from the database)
	if dbCount(t, h, u.ID) != 1 {
		t.Fatal("database row missing")
	}
	if _, ok := storeValue(t, store, "api-key:by-id:"+k.ID); !ok {
		t.Fatal("cache entry missing")
	}
	if _, ok := storeValue(t, store, "api-key:by-ref:"+u.ID); ok {
		t.Fatal("by-ref list should not be kept with fallback")
	}
	// Step 2: a cache miss reads the database and fills the cache
	_ = store.Delete(context.Background(), "api-key:"+apikey.HashKey(k.Key))
	_ = store.Delete(context.Background(), "api-key:by-id:"+k.ID)
	if r := h.verify(t, k.Key, nil); !r.Valid {
		t.Fatalf("verify = %+v", r.Error)
	}
	if _, ok := storeValue(t, store, "api-key:"+apikey.HashKey(k.Key)); !ok {
		t.Fatal("cache not refilled")
	}
	// the usage update went to the database too
	rec, err := h.Auth.Adapter().FindOne(context.Background(), "apikey", []adapter.Where{{Field: "id", Value: k.ID}})
	if err != nil || rec["requestCount"] != float64(1) {
		t.Fatalf("db requestCount = %v (%v)", rec["requestCount"], err)
	}
	// Step 3: listing builds the owner list from the database
	var list struct {
		Total int `json:"total"`
	}
	expectOK(t, h.Get(t, "/api/auth/api-key/list", u.as()), &list)
	if ref, ok := storeValue(t, store, "api-key:by-ref:"+u.ID); list.Total != 1 || !ok || ref != `["`+k.ID+`"]` {
		t.Fatalf("list = %d, by-ref = %q", list.Total, ref)
	}
	// Step 4: delete removes it everywhere
	expectOK(t, h.Post(t, "/api/auth/api-key/delete", map[string]any{"keyId": k.ID}, u.as()), nil)
	if dbCount(t, h, u.ID) != 0 {
		t.Fatal("database row left")
	}
	if _, ok := storeValue(t, store, "api-key:by-id:"+k.ID); ok {
		t.Fatal("cache entry left")
	}
}

// mapStorage is a CustomStorage recording TTLs.
type mapStorage struct {
	mu   sync.Mutex
	data map[string]string
	ttl  map[string]time.Duration
}

func (m *mapStorage) Get(_ context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[key]
	return v, ok, nil
}

func (m *mapStorage) Set(_ context.Context, key, value string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key], m.ttl[key] = value, ttl
	return nil
}

func (m *mapStorage) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func TestCustomStorageAndTTL(t *testing.T) {
	custom := &mapStorage{data: map[string]string{}, ttl: map[string]time.Duration{}}
	h := newHarness(t,
		withConfigs(apikeyconfig.Configuration{Storage: apikeyconfig.StorageSecondary, CustomStorage: custom}),
		withServer(compattest.WithoutSecondaryStorage()))
	u := h.signUp(t)
	k := h.createKey(t, u, map[string]any{"expiresIn": 86400})
	// Step 1: the custom store holds the key with the seconds left until expiry as TTL
	key := "api-key:by-id:" + k.ID
	if _, ok := custom.data[key]; !ok {
		t.Fatalf("custom storage = %v", custom.data)
	}
	if ttl := custom.ttl[key]; ttl != 86400*time.Second && ttl != 86399*time.Second {
		t.Fatalf("ttl = %v", ttl)
	}
	if custom.ttl["api-key:by-ref:"+u.ID] != 0 {
		t.Fatal("owner list must not expire")
	}
	// Step 2: verification reads it back and writes the usage
	if r := h.verify(t, k.Key, nil); !r.Valid {
		t.Fatalf("verify = %+v", r.Error)
	}
	var stored map[string]any
	_ = json.Unmarshal([]byte(custom.data[key]), &stored)
	if stored["requestCount"] != float64(1) {
		t.Fatalf("stored = %v", stored)
	}
	// Step 3: a key without expiry has no TTL
	k2 := h.createKey(t, u, nil)
	if custom.ttl["api-key:by-id:"+k2.ID] != 0 {
		t.Fatal("ttl without expiry")
	}
}

// TestSecondaryStorageRequiresStore checks setup fails without a store for secondary-storage keys.
func TestSecondaryStorageRequiresStore(t *testing.T) {
	p := apikey.New(apikeyconfig.Configuration{Storage: apikeyconfig.StorageSecondary})
	_, err := p.CreateAPIKey(context.Background(), apikey.CreateAPIKeyInput{})
	if err == nil {
		t.Fatal("uninitialized plugin must fail")
	}
}
