package test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	apikey "github.com/better-go-auth/goauth/src/plugins/api-key"
	apikeyconfig "github.com/better-go-auth/goauth/src/plugins/api-key/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

// TestLegacyDoubleEncodedMetadata checks metadata written double-encoded by older better-auth versions is
// returned as an object and rewritten once read.
func TestLegacyDoubleEncodedMetadata(t *testing.T) {
	h := newHarness(t, withConfigs(apikeyconfig.Configuration{EnableMetadata: true}))
	u := h.signUp(t)
	k := h.createKey(t, u, map[string]any{"metadata": map[string]any{"plan": "pro"}})
	ctx := context.Background()
	where := []adapter.Where{{Field: "id", Value: k.ID}}
	// Step 1: store JSON.stringify(JSON.stringify(metadata)), like better-auth < 1.4 did
	_, err := h.Auth.Adapter().Update(ctx, "apikey", where, adapter.Record{"metadata": `"{\"plan\":\"pro\"}"`})
	if err != nil {
		t.Fatal(err)
	}
	// Step 2: list decodes it without writing; get decodes it and rewrites the row
	var list struct {
		APIKeys []keyBody `json:"apiKeys"`
	}
	expectOK(t, h.Get(t, "/api/auth/api-key/list", u.as()), &list)
	if list.APIKeys[0].Metadata.(map[string]any)["plan"] != "pro" {
		t.Fatalf("list metadata = %#v", list.APIKeys[0].Metadata)
	}
	_, _ = h.Auth.Adapter().Update(ctx, "apikey", where, adapter.Record{"metadata": `"{\"plan\":\"pro\"}"`})
	var got keyBody
	expectOK(t, h.Get(t, "/api/auth/api-key/get?id="+k.ID, u.as()), &got)
	if got.Metadata.(map[string]any)["plan"] != "pro" {
		t.Fatalf("get metadata = %#v", got.Metadata)
	}
	rec, err := h.Auth.Adapter().FindOne(ctx, "apikey", where)
	if err != nil || rec["metadata"] != `{"plan":"pro"}` {
		t.Fatalf("row metadata = %#v (%v)", rec["metadata"], err)
	}
}

// vanishingStorage is a custom storage whose key entries disappear after the first read (a concurrent
// delete between validation and the usage write).
type vanishingStorage struct {
	mapStorage
	reads map[string]int
	once  sync.Mutex
}

func (v *vanishingStorage) Get(ctx context.Context, key string) (string, bool, error) {
	v.once.Lock()
	v.reads[key]++
	n := v.reads[key]
	v.once.Unlock()
	if strings.HasPrefix(key, "api-key:") && !strings.Contains(key, ":by-") && n > 1 {
		return "", false, nil
	}
	return v.mapStorage.Get(ctx, key)
}

// TestFailedToUpdateAPIKey checks a key deleted between validation and the usage write fails the
// verification with FAILED_TO_UPDATE_API_KEY.
func TestFailedToUpdateAPIKey(t *testing.T) {
	store := &vanishingStorage{mapStorage: mapStorage{data: map[string]string{}, ttl: map[string]time.Duration{}}, reads: map[string]int{}}
	h := newHarness(t,
		withConfigs(apikeyconfig.Configuration{Storage: apikeyconfig.StorageSecondary, CustomStorage: store}),
		withServer(compattest.WithoutSecondaryStorage()))
	u := h.signUp(t)
	k := h.serverKey(t, apikey.CreateAPIKeyInput{UserID: &u.ID})
	expectInvalid(t, h.verify(t, k.Key, nil), "FAILED_TO_UPDATE_API_KEY", "Failed to update API key")
}

// TestSchemaRenames checks the schema option (table and column names) end to end.
func TestSchemaRenames(t *testing.T) {
	h := newHarness(t, withPluginOptions(apikey.WithSchema(apikeyconfig.SchemaOptions{
		ModelName: "api_keys", Fields: map[string]string{"referenceId": "owner_id", "key": "key_hash"},
	})))
	u := h.signUp(t)
	k := h.createKey(t, u, nil)
	if !h.verify(t, k.Key, nil).Valid {
		t.Fatal("verify")
	}
	var n int64
	if err := h.DB.Raw("SELECT COUNT(*) FROM api_keys WHERE owner_id = ? AND key_hash = ?", u.ID, apikey.HashKey(k.Key)).Scan(&n).Error; err != nil || n != 1 {
		t.Fatalf("renamed table: %d (%v)", n, err)
	}
}
