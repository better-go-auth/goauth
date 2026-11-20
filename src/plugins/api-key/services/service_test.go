package services

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/plugins/api-key/config"
)

// TestHashKeyMatchesBetterAuth checks defaultKeyHasher vectors computed with @better-auth/api-key 1.6.16.
func TestHashKeyMatchesBetterAuth(t *testing.T) {
	vectors := map[string]string{
		"test-key":                "Yq-HBHZPr46oL8Yc6cTDkItsuX1GOmNOnlh9fIhdsO8",
		"goauth_AbCdEfGhIjKlMnOp": "kXk1DfQyWzkZ84nSRbx8DT4jrYki3yXyd_2It4_O-V4",
		"ünïcødé🔑":                "h3gbmfUgkoxRj_SPqf7BwRXBgxRsaLf6D34BUme7Rh0",
	}
	for in, want := range vectors {
		if got := HashKey(in); got != want {
			t.Errorf("HashKey(%q) = %q, want %q", in, got, want)
		}
	}
	// disabled hashing stores the key itself
	if got := hashFor("plain", config.Configuration{DisableKeyHashing: true}); got != "plain" {
		t.Fatalf("hashFor with DisableKeyHashing = %q", got)
	}
}

func TestRandomLettersAndGenerator(t *testing.T) {
	// Step 1: only letters, requested length
	s := randomLetters(500)
	if len(s) != 500 {
		t.Fatalf("len = %d", len(s))
	}
	for _, c := range s {
		if !strings.ContainsRune(letters, c) {
			t.Fatalf("unexpected character %q", c)
		}
	}
	// Step 2: the default generator prepends the prefix; a custom one gets length and prefix
	opts := config.Configuration{}.WithDefaults()
	k, err := generateKey(context.Background(), opts, "pre_")
	if err != nil || !strings.HasPrefix(k, "pre_") || len(k) != 4+64 {
		t.Fatalf("generateKey = %q, %v", k, err)
	}
	opts.CustomKeyGenerator = func(_ context.Context, length int, prefix string) (string, error) {
		return prefix + strings.Repeat("x", length), nil
	}
	opts.DefaultKeyLength = 3
	if k, _ := generateKey(context.Background(), opts, "p"); k != "pxxx" {
		t.Fatalf("custom generator = %q", k)
	}
}

func i64(v int64) *int64 { return &v }

func TestIsRateLimited(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	opts := config.Configuration{}.WithDefaults()
	base := func() *APIKey {
		return &APIKey{RateLimitEnabled: true, RateLimitTimeWindow: i64(1000), RateLimitMax: i64(2)}
	}
	// Step 1: disabled for the configuration or the key: only lastRequest is recorded
	off := false
	cfgOff := opts
	cfgOff.RateLimit.Enabled = &off
	if r := isRateLimited(base(), cfgOff, now); !r.success || r.lastRequest == nil || r.requestCount != nil {
		t.Fatalf("config off: %+v", r)
	}
	k := base()
	k.RateLimitEnabled = false
	if r := isRateLimited(k, opts, now); !r.success || r.lastRequest == nil || r.requestCount != nil {
		t.Fatalf("key off: %+v", r)
	}
	// Step 2: no window or max: nothing recorded
	k = base()
	k.RateLimitMax = nil
	if r := isRateLimited(k, opts, now); !r.success || r.lastRequest != nil || r.requestCount != nil {
		t.Fatalf("no max: %+v", r)
	}
	// Step 3: first request starts a window
	k = base()
	if r := isRateLimited(k, opts, now); !r.success || *r.requestCount != 1 {
		t.Fatalf("first: %+v", r)
	}
	// Step 4: inside the window: count up to max, then refuse with tryAgainIn
	last := now.Add(-400 * time.Millisecond)
	k.LastRequest, k.RequestCount = &last, 1
	if r := isRateLimited(k, opts, now); !r.success || *r.requestCount != 2 {
		t.Fatalf("second: %+v", r)
	}
	k.RequestCount = 2
	if r := isRateLimited(k, opts, now); r.success || r.tryAgainIn != 600 {
		t.Fatalf("over: %+v", r)
	}
	// Step 5: after the window: a new one (exactly the window length is still inside)
	last = now.Add(-1000 * time.Millisecond)
	k.LastRequest = &last
	if r := isRateLimited(k, opts, now); r.success {
		t.Fatalf("boundary should still be limited: %+v", r)
	}
	last = now.Add(-1001 * time.Millisecond)
	k.LastRequest = &last
	if r := isRateLimited(k, opts, now); !r.success || *r.requestCount != 1 {
		t.Fatalf("new window: %+v", r)
	}
}

func TestJSHelpers(t *testing.T) {
	// Step 1: truthiness
	for _, v := range []any{nil, false, "", float64(0)} {
		if jsTruthy(v) {
			t.Errorf("%#v should be falsy", v)
		}
	}
	for _, v := range []any{true, "x", float64(1), map[string]any{}, []any{}} {
		if !jsTruthy(v) {
			t.Errorf("%#v should be truthy", v)
		}
	}
	// Step 2: typeof object
	for _, v := range []any{nil, map[string]any{}, []any{}} {
		if !isJSObject(v) {
			t.Errorf("%#v should be an object", v)
		}
	}
	for _, v := range []any{"s", float64(1), true} {
		if isJSObject(v) {
			t.Errorf("%#v should not be an object", v)
		}
	}
	// Step 3: UTF-16 lengths
	if jsLength("🔑ab") != 4 || jsSubstring("🔑abc", 3) != "🔑a" || jsSubstring("ab", 6) != "ab" {
		t.Fatal("UTF-16 helpers")
	}
	// Step 4: Go values become their JSON form
	type meta struct {
		Plan string `json:"plan"`
	}
	if m, ok := normalizeJSON(meta{Plan: "pro"}).(map[string]any); !ok || m["plan"] != "pro" {
		t.Fatalf("normalizeJSON struct = %#v", normalizeJSON(meta{Plan: "pro"}))
	}
}

func TestMetadataEncoding(t *testing.T) {
	// Step 1: the column holds JSON.stringify(value); reading parses it once
	col := encodeMetadataColumn(map[string]any{"a": float64(1)})
	if col != `{"a":1}` {
		t.Fatalf("column = %#v", col)
	}
	if m := decodeMetadataColumn(col).(map[string]any); m["a"] != float64(1) {
		t.Fatalf("decoded = %#v", m)
	}
	if encodeMetadataColumn(nil) != nil || decodeMetadataColumn(nil) != nil || decodeMetadataColumn("") != nil {
		t.Fatal("null metadata")
	}
	// Step 2: legacy double-encoded rows decode to a string first, then to the object
	legacy := decodeMetadataColumn(`"{\"a\":1}"`)
	if !needsMetadataMigration(legacy) {
		t.Fatalf("legacy value = %#v", legacy)
	}
	if m, ok := ParseMetadata(legacy).(map[string]any); !ok || m["a"] != float64(1) {
		t.Fatalf("ParseMetadata = %#v", ParseMetadata(legacy))
	}
	if ParseMetadata("not json") != nil {
		t.Fatal("invalid legacy metadata should be null")
	}
}

func TestStorageSerializationRoundTrip(t *testing.T) {
	now := time.Date(2026, 3, 4, 5, 6, 7, 8_000_000, time.UTC)
	exp := now.Add(time.Hour)
	perms := `{"files":["read"]}`
	name := "n"
	k := &APIKey{
		ID: "id1", ConfigID: "default", Name: &name, ReferenceID: "u1", Key: "hash", Enabled: true,
		RateLimitEnabled: true, RateLimitTimeWindow: i64(1000), RateLimitMax: i64(5), RequestCount: 3,
		Remaining: i64(7), ExpiresAt: &exp, CreatedAt: now, UpdatedAt: now, Permissions: &perms,
		Metadata: map[string]any{"plan": "pro"},
	}
	// Step 1: better-auth's JSON: ISO dates, permissions as a JSON string, metadata as an object
	s, err := serializeAPIKey(k)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		t.Fatal(err)
	}
	if raw["createdAt"] != "2026-03-04T05:06:07.008Z" || raw["lastRequest"] != nil || raw["permissions"] != perms {
		t.Fatalf("serialized = %s", s)
	}
	if md, ok := raw["metadata"].(map[string]any); !ok || md["plan"] != "pro" {
		t.Fatalf("metadata = %#v", raw["metadata"])
	}
	// Step 2: and back
	back := deserializeAPIKey(s)
	if back == nil || back.ID != "id1" || *back.Remaining != 7 || back.RequestCount != 3 || !back.ExpiresAt.Equal(exp) ||
		!back.CreatedAt.Equal(now) || *back.Name != "n" || back.ParsedPermissions()["files"][0] != "read" {
		t.Fatalf("round trip = %+v", back)
	}
	if deserializeAPIKey("garbage") != nil || deserializeAPIKey("") != nil {
		t.Fatal("junk must not deserialize")
	}
}

func TestResolveConfiguration(t *testing.T) {
	// Step 1: one configuration without id is the default (returned as "default")
	s := New(Deps{Configurations: []config.Configuration{config.Configuration{}.WithDefaults()}})
	c, err := s.ResolveConfiguration("")
	if err != nil || c.ConfigID != "default" {
		t.Fatalf("default = %+v, %v", c.ConfigID, err)
	}
	if c, _ := s.ResolveConfiguration("unknown"); c.ConfigID != "default" {
		t.Fatalf("unknown falls back to default, got %q", c.ConfigID)
	}
	// Step 2: named configurations without a default: unknown ids fail
	s = New(Deps{Configurations: []config.Configuration{
		config.Configuration{ConfigID: "a"}.WithDefaults(), config.Configuration{ConfigID: "b"}.WithDefaults(),
	}})
	if c, err := s.ResolveConfiguration("b"); err != nil || c.ConfigID != "b" {
		t.Fatalf("b = %q, %v", c.ConfigID, err)
	}
	_, err = s.ResolveConfiguration("")
	var ae *autherr.AuthError
	if !errors.As(err, &ae) || ae.Code != "NO_DEFAULT_API_KEY_CONFIGURATION_FOUND" || ae.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing default: %v", err)
	}
	// Step 3: configId matching treats "", "default" alike
	if !config.ConfigIDMatches("", "default") || !config.ConfigIDMatches("default", "") || config.ConfigIDMatches("a", "default") {
		t.Fatal("ConfigIDMatches")
	}
}

func TestValidateConfigurations(t *testing.T) {
	if err := config.ValidateConfigurations([]config.Configuration{{ConfigID: "a"}, {}}); err == nil {
		t.Fatal("missing configId must fail")
	}
	if err := config.ValidateConfigurations([]config.Configuration{{ConfigID: "a"}, {ConfigID: "a"}}); err == nil {
		t.Fatal("duplicate configId must fail")
	}
	if err := config.ValidateConfigurations([]config.Configuration{{Storage: "redis"}}); err == nil {
		t.Fatal("unknown storage must fail")
	}
	if err := config.ValidateConfigurations([]config.Configuration{{References: "team"}}); err == nil {
		t.Fatal("unknown references must fail")
	}
	if err := config.ValidateConfigurations([]config.Configuration{{}}); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationDefaults(t *testing.T) {
	c := config.Configuration{}.WithDefaults()
	if c.APIKeyHeaders[0] != "x-api-key" || c.DefaultKeyLength != 64 || c.MaximumPrefixLength != 32 ||
		c.MinimumPrefixLength != 1 || c.MaximumNameLength != 32 || c.MinimumNameLength != 1 ||
		c.Storage != config.StorageDatabase || c.References != config.ReferencesUser || !c.RateLimitEnabled() ||
		c.RateLimit.TimeWindow != 24*time.Hour || *c.RateLimit.MaxRequests != 10 || *c.KeyExpiration.MaxExpiresIn != 365 ||
		*c.KeyExpiration.MinExpiresIn != 1 || !*c.StartingCharactersConfig.ShouldStore ||
		c.StartingCharactersConfig.CharactersLength != 6 || c.EnableMetadata {
		t.Fatalf("defaults = %+v", c)
	}
}

func TestSortKeys(t *testing.T) {
	a, b, c := "a", "b", "c"
	keys := []*APIKey{{ID: "2", Name: &b}, {ID: "n"}, {ID: "1", Name: &a}, {ID: "3", Name: &c}}
	// nulls first ascending, last descending
	got := sortKeys(append([]*APIKey(nil), keys...), &sortSpec{Field: FieldName})
	if got[0].ID != "n" || got[1].ID != "1" || got[3].ID != "3" {
		t.Fatalf("asc = %v %v %v %v", got[0].ID, got[1].ID, got[2].ID, got[3].ID)
	}
	got = sortKeys(append([]*APIKey(nil), keys...), &sortSpec{Field: FieldName, Desc: true})
	if got[0].ID != "3" || got[3].ID != "n" {
		t.Fatalf("desc = %v ... %v", got[0].ID, got[3].ID)
	}
	if storageIdentifier(config.Configuration{Storage: config.StorageDatabase}) != "database" ||
		storageIdentifier(config.Configuration{Storage: config.StorageSecondary, FallbackToDatabase: true}) != "secondary-storage-with-fallback" ||
		storageIdentifier(config.Configuration{Storage: config.StorageSecondary}) != "secondary-storage" {
		t.Fatal("storageIdentifier")
	}
}

func TestErrorBodies(t *testing.T) {
	// Step 1: RATE_LIMITED carries details.tryAgainIn
	body, status, ok := ErrorBody(&RateLimitedError{TryAgainIn: 42})
	if !ok || status != http.StatusTooManyRequests || body["code"] != "RATE_LIMITED" || body["message"] != "Rate limit exceeded." ||
		body["details"].(map[string]any)["tryAgainIn"] != int64(42) {
		t.Fatalf("rate limited body = %#v", body)
	}
	// Step 2: API errors are {code, message}; others are not API errors
	body, status, ok = ErrorBody(ErrKeyExpired)
	if !ok || status != http.StatusUnauthorized || body["code"] != "KEY_EXPIRED" || body["message"] != "API Key has expired" {
		t.Fatalf("api error body = %#v", body)
	}
	if _, _, ok := ErrorBody(errors.New("boom")); ok {
		t.Fatal("plain errors are not API errors")
	}
	// Step 3: every code has its better-auth message (31 codes in 1.6.16)
	if len(ErrorCodes) != 31 {
		t.Fatalf("len(ErrorCodes) = %d", len(ErrorCodes))
	}
}
