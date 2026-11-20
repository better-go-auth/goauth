package services

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/models/dtos"
)

// ModelName is the logical model (and default table) name of API keys (better-auth's API_KEY_TABLE_NAME).
const ModelName = "apikey"

// Logical field names of the apikey model (better-auth's apiKeySchema).
const (
	FieldID                  = "id"
	FieldConfigID            = "configId"
	FieldName                = "name"
	FieldStart               = "start"
	FieldReferenceID         = "referenceId"
	FieldPrefix              = "prefix"
	FieldKey                 = "key"
	FieldRefillInterval      = "refillInterval"
	FieldRefillAmount        = "refillAmount"
	FieldLastRefillAt        = "lastRefillAt"
	FieldEnabled             = "enabled"
	FieldRateLimitEnabled    = "rateLimitEnabled"
	FieldRateLimitTimeWindow = "rateLimitTimeWindow"
	FieldRateLimitMax        = "rateLimitMax"
	FieldRequestCount        = "requestCount"
	FieldRemaining           = "remaining"
	FieldLastRequest         = "lastRequest"
	FieldExpiresAt           = "expiresAt"
	FieldCreatedAt           = "createdAt"
	FieldUpdatedAt           = "updatedAt"
	FieldPermissions         = "permissions"
	FieldMetadata            = "metadata"
)

// APIKey is a stored API key: a row of the apikey table or a key in the secondary storage.
type APIKey struct {
	ID       string
	ConfigID string
	Name     *string
	// Start holds the first characters of the key (prefix included) when configured.
	Start *string
	// ReferenceID is the owner: a user id, or an organization id for organization-referenced keys.
	ReferenceID string
	Prefix      *string
	// Key is the SHA-256 hash of the key (base64url, no padding), or the key itself with DisableKeyHashing.
	Key string
	// RefillInterval is the refill period in milliseconds; RefillAmount the value `remaining` is reset to.
	RefillInterval *int64
	RefillAmount   *int64
	LastRefillAt   *time.Time
	Enabled        bool
	// RateLimitEnabled, RateLimitTimeWindow (ms) and RateLimitMax are the key's rate limit;
	// RequestCount counts the requests of the current window.
	RateLimitEnabled    bool
	RateLimitTimeWindow *int64
	RateLimitMax        *int64
	RequestCount        int64
	// Remaining is the number of uses left (nil = unlimited).
	Remaining   *int64
	LastRequest *time.Time
	ExpiresAt   *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
	// Permissions is the stored JSON of the key's permissions ({resource: [actions]}) or nil.
	Permissions *string
	// Metadata is the stored metadata as better-auth's adapter reads it (the JSON column parsed once): an
	// object, nil, or a JSON string for legacy double-encoded rows (see ParseMetadata).
	Metadata any
}

// APIKeyResponse is an API key as the endpoints return it (better-auth's ApiKey without `key`): the
// metadata object and the permissions decoded.
type APIKeyResponse struct {
	ID                  string              `json:"id"`
	ConfigID            string              `json:"configId"`
	Name                *string             `json:"name"`
	Start               *string             `json:"start"`
	Prefix              *string             `json:"prefix"`
	ReferenceID         string              `json:"referenceId"`
	RefillInterval      *int64              `json:"refillInterval"`
	RefillAmount        *int64              `json:"refillAmount"`
	LastRefillAt        *dtos.Time          `json:"lastRefillAt"`
	Enabled             bool                `json:"enabled"`
	RateLimitEnabled    bool                `json:"rateLimitEnabled"`
	RateLimitTimeWindow *int64              `json:"rateLimitTimeWindow"`
	RateLimitMax        *int64              `json:"rateLimitMax"`
	RequestCount        int64               `json:"requestCount"`
	Remaining           *int64              `json:"remaining"`
	LastRequest         *dtos.Time          `json:"lastRequest"`
	ExpiresAt           *dtos.Time          `json:"expiresAt"`
	CreatedAt           dtos.Time           `json:"createdAt"`
	UpdatedAt           dtos.Time           `json:"updatedAt"`
	Metadata            any                 `json:"metadata"`
	Permissions         map[string][]string `json:"permissions"`
}

// CreateAPIKeyResponse is the body of POST /api-key/create: the key with its plain value, which is only
// ever returned here.
type CreateAPIKeyResponse struct {
	APIKeyResponse
	// Key is the plain API key.
	Key string `json:"key"`
}

// Response returns the key as the endpoints return it, with metadata as given.
func (k *APIKey) Response(metadata any) APIKeyResponse {
	return APIKeyResponse{
		ID:                  k.ID,
		ConfigID:            k.ConfigID,
		Name:                k.Name,
		Start:               k.Start,
		Prefix:              k.Prefix,
		ReferenceID:         k.ReferenceID,
		RefillInterval:      k.RefillInterval,
		RefillAmount:        k.RefillAmount,
		LastRefillAt:        timePtr(k.LastRefillAt),
		Enabled:             k.Enabled,
		RateLimitEnabled:    k.RateLimitEnabled,
		RateLimitTimeWindow: k.RateLimitTimeWindow,
		RateLimitMax:        k.RateLimitMax,
		RequestCount:        k.RequestCount,
		Remaining:           k.Remaining,
		LastRequest:         timePtr(k.LastRequest),
		ExpiresAt:           timePtr(k.ExpiresAt),
		CreatedAt:           dtos.Time(k.CreatedAt),
		UpdatedAt:           dtos.Time(k.UpdatedAt),
		Metadata:            metadata,
		Permissions:         k.ParsedPermissions(),
	}
}

// ParsedPermissions decodes the stored permissions (nil when there are none or they are not valid JSON,
// like better-auth's safeJSONParse).
func (k *APIKey) ParsedPermissions() map[string][]string {
	if k.Permissions == nil || *k.Permissions == "" {
		return nil
	}
	var out map[string][]string
	if err := json.Unmarshal([]byte(*k.Permissions), &out); err != nil {
		return nil
	}
	return out
}

// ParseMetadata returns the key's metadata object: a legacy double-encoded value (a JSON string) is
// decoded once more (better-auth's parseDoubleStringifiedMetadata).
func ParseMetadata(metadata any) any {
	s, ok := metadata.(string)
	if !ok {
		return metadata
	}
	var out any
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}

// needsMetadataMigration reports whether metadata is a legacy double-encoded value.
func needsMetadataMigration(metadata any) bool {
	_, ok := metadata.(string)
	return ok
}

// timePtr converts an optional time to the JSON time type.
func timePtr(t *time.Time) *dtos.Time {
	if t == nil {
		return nil
	}
	v := dtos.Time(*t)
	return &v
}

// ─── Database records ────────────────────────────────────────────────────────

// record returns the key as an adapter record (logical field names). The id is left out when empty so
// the adapter generates it.
func (k *APIKey) record() adapter.Record {
	rec := adapter.Record{
		FieldConfigID:            k.ConfigID,
		FieldName:                strPtrValue(k.Name),
		FieldStart:               strPtrValue(k.Start),
		FieldReferenceID:         k.ReferenceID,
		FieldPrefix:              strPtrValue(k.Prefix),
		FieldKey:                 k.Key,
		FieldRefillInterval:      numValue(k.RefillInterval),
		FieldRefillAmount:        numValue(k.RefillAmount),
		FieldLastRefillAt:        timeValue(k.LastRefillAt),
		FieldEnabled:             k.Enabled,
		FieldRateLimitEnabled:    k.RateLimitEnabled,
		FieldRateLimitTimeWindow: numValue(k.RateLimitTimeWindow),
		FieldRateLimitMax:        numValue(k.RateLimitMax),
		FieldRequestCount:        float64(k.RequestCount),
		FieldRemaining:           numValue(k.Remaining),
		FieldLastRequest:         timeValue(k.LastRequest),
		FieldExpiresAt:           timeValue(k.ExpiresAt),
		FieldCreatedAt:           k.CreatedAt,
		FieldUpdatedAt:           k.UpdatedAt,
		FieldPermissions:         strPtrValue(k.Permissions),
		FieldMetadata:            encodeMetadataColumn(k.Metadata),
	}
	if k.ID != "" {
		rec[FieldID] = k.ID
	}
	return rec
}

// fromRecord reads an adapter record (better-auth's adapter output: metadata parsed once).
func fromRecord(rec adapter.Record) *APIKey {
	k := &APIKey{
		ID:                  str(rec[FieldID]),
		ConfigID:            str(rec[FieldConfigID]),
		Name:                strPtr(rec[FieldName]),
		Start:               strPtr(rec[FieldStart]),
		ReferenceID:         str(rec[FieldReferenceID]),
		Prefix:              strPtr(rec[FieldPrefix]),
		Key:                 str(rec[FieldKey]),
		RefillInterval:      intPtr(rec[FieldRefillInterval]),
		RefillAmount:        intPtr(rec[FieldRefillAmount]),
		LastRefillAt:        timeOf(rec[FieldLastRefillAt]),
		Enabled:             boolOr(rec[FieldEnabled], true),
		RateLimitEnabled:    boolOr(rec[FieldRateLimitEnabled], true),
		RateLimitTimeWindow: intPtr(rec[FieldRateLimitTimeWindow]),
		RateLimitMax:        intPtr(rec[FieldRateLimitMax]),
		Remaining:           intPtr(rec[FieldRemaining]),
		LastRequest:         timeOf(rec[FieldLastRequest]),
		ExpiresAt:           timeOf(rec[FieldExpiresAt]),
		Permissions:         strPtr(rec[FieldPermissions]),
		Metadata:            decodeMetadataColumn(rec[FieldMetadata]),
	}
	if n := intPtr(rec[FieldRequestCount]); n != nil {
		k.RequestCount = *n
	}
	if t := timeOf(rec[FieldCreatedAt]); t != nil {
		k.CreatedAt = *t
	}
	if t := timeOf(rec[FieldUpdatedAt]); t != nil {
		k.UpdatedAt = *t
	}
	return k
}

// encodeMetadataColumn is better-auth's metadata transform.input (JSON.stringify); nil stays NULL.
func encodeMetadataColumn(v any) any {
	if v == nil {
		return nil
	}
	raw, err := marshalJS(v)
	if err != nil {
		return nil
	}
	return string(raw)
}

// decodeMetadataColumn is better-auth's metadata transform.output (empty → null, else parseJSON).
func decodeMetadataColumn(v any) any {
	s, ok := v.(string)
	if !ok || s == "" {
		if raw, isRaw := v.(json.RawMessage); isRaw && len(raw) > 0 {
			s = string(raw)
		} else {
			return nil
		}
	}
	var out any
	if err := json.Unmarshal([]byte(strings.TrimSpace(s)), &out); err != nil {
		return nil
	}
	return out
}

// ─── Secondary storage JSON ──────────────────────────────────────────────────

// storedKey is better-auth's serializeApiKey JSON (dates as ISO strings).
type storedKey struct {
	ID                  string     `json:"id"`
	ConfigID            string     `json:"configId"`
	Name                *string    `json:"name"`
	Start               *string    `json:"start"`
	ReferenceID         string     `json:"referenceId"`
	Prefix              *string    `json:"prefix"`
	Key                 string     `json:"key"`
	RefillInterval      *float64   `json:"refillInterval"`
	RefillAmount        *float64   `json:"refillAmount"`
	LastRefillAt        *dtos.Time `json:"lastRefillAt"`
	Enabled             *bool      `json:"enabled"`
	RateLimitEnabled    *bool      `json:"rateLimitEnabled"`
	RateLimitTimeWindow *float64   `json:"rateLimitTimeWindow"`
	RateLimitMax        *float64   `json:"rateLimitMax"`
	RequestCount        *float64   `json:"requestCount"`
	Remaining           *float64   `json:"remaining"`
	LastRequest         *dtos.Time `json:"lastRequest"`
	ExpiresAt           *dtos.Time `json:"expiresAt"`
	CreatedAt           dtos.Time  `json:"createdAt"`
	UpdatedAt           dtos.Time  `json:"updatedAt"`
	Permissions         *string    `json:"permissions"`
	Metadata            any        `json:"metadata"`
}

// serializeAPIKey is better-auth's serializeApiKey.
func serializeAPIKey(k *APIKey) (string, error) {
	enabled, rlEnabled := k.Enabled, k.RateLimitEnabled
	rc := float64(k.RequestCount)
	raw, err := marshalJS(storedKey{
		ID: k.ID, ConfigID: k.ConfigID, Name: k.Name, Start: k.Start, ReferenceID: k.ReferenceID,
		Prefix: k.Prefix, Key: k.Key, RefillInterval: floatPtr(k.RefillInterval), RefillAmount: floatPtr(k.RefillAmount),
		LastRefillAt: timePtr(k.LastRefillAt), Enabled: &enabled, RateLimitEnabled: &rlEnabled,
		RateLimitTimeWindow: floatPtr(k.RateLimitTimeWindow), RateLimitMax: floatPtr(k.RateLimitMax),
		RequestCount: &rc, Remaining: floatPtr(k.Remaining), LastRequest: timePtr(k.LastRequest),
		ExpiresAt: timePtr(k.ExpiresAt), CreatedAt: dtos.Time(k.CreatedAt), UpdatedAt: dtos.Time(k.UpdatedAt),
		Permissions: k.Permissions, Metadata: k.Metadata,
	})
	return string(raw), err
}

// deserializeAPIKey is better-auth's deserializeApiKey (nil for anything that is not a stored key).
func deserializeAPIKey(data string) *APIKey {
	if data == "" {
		return nil
	}
	var s storedKey
	if err := json.Unmarshal([]byte(data), &s); err != nil {
		return nil
	}
	k := &APIKey{
		ID: s.ID, ConfigID: s.ConfigID, Name: s.Name, Start: s.Start, ReferenceID: s.ReferenceID, Prefix: s.Prefix,
		Key: s.Key, RefillInterval: intFromFloat(s.RefillInterval), RefillAmount: intFromFloat(s.RefillAmount),
		LastRefillAt: fromDTOTime(s.LastRefillAt), Enabled: s.Enabled == nil || *s.Enabled,
		RateLimitEnabled: s.RateLimitEnabled == nil || *s.RateLimitEnabled, RateLimitTimeWindow: intFromFloat(s.RateLimitTimeWindow),
		RateLimitMax: intFromFloat(s.RateLimitMax), Remaining: intFromFloat(s.Remaining), LastRequest: fromDTOTime(s.LastRequest),
		ExpiresAt: fromDTOTime(s.ExpiresAt), CreatedAt: time.Time(s.CreatedAt).UTC(), UpdatedAt: time.Time(s.UpdatedAt).UTC(),
		Permissions: s.Permissions, Metadata: s.Metadata,
	}
	if s.RequestCount != nil {
		k.RequestCount = int64(*s.RequestCount)
	}
	return k
}

// ─── Value helpers ───────────────────────────────────────────────────────────

// marshalJS encodes v like JSON.stringify (no HTML escaping, no trailing newline).
func marshalJS(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// jsLength is JavaScript's String.prototype.length (UTF-16 code units).
func jsLength(s string) int { return len(utf16.Encode([]rune(s))) }

// jsSubstring is JavaScript's s.substring(0, n) (UTF-16 code units).
func jsSubstring(s string, n int) string {
	u := utf16.Encode([]rune(s))
	if n >= len(u) {
		return s
	}
	return string(utf16.Decode(u[:n]))
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func strPtr(v any) *string {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	return &s
}

func strPtrValue(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

// intPtr reads a number column (float64 / int64 / json.Number) as an optional integer.
func intPtr(v any) *int64 {
	var n int64
	switch x := v.(type) {
	case float64:
		n = int64(math.Round(x))
	case float32:
		n = int64(math.Round(float64(x)))
	case int64:
		n = x
	case int:
		n = int64(x)
	case int32:
		n = int64(x)
	case json.Number:
		f, err := x.Float64()
		if err != nil {
			return nil
		}
		n = int64(math.Round(f))
	default:
		return nil
	}
	return &n
}

func numValue(p *int64) any {
	if p == nil {
		return nil
	}
	return float64(*p)
}

func floatPtr(p *int64) *float64 {
	if p == nil {
		return nil
	}
	f := float64(*p)
	return &f
}

func intFromFloat(p *float64) *int64 {
	if p == nil {
		return nil
	}
	n := int64(math.Round(*p))
	return &n
}

func timeOf(v any) *time.Time {
	t, ok := v.(time.Time)
	if !ok || t.IsZero() {
		return nil
	}
	t = t.UTC()
	return &t
}

func timeValue(p *time.Time) any {
	if p == nil {
		return nil
	}
	return *p
}

func fromDTOTime(t *dtos.Time) *time.Time {
	if t == nil || time.Time(*t).IsZero() {
		return nil
	}
	v := time.Time(*t).UTC()
	return &v
}

func boolOr(v any, def bool) bool {
	switch b := v.(type) {
	case bool:
		return b
	case int64:
		return b != 0
	case float64:
		return b != 0
	}
	return def
}

// jsTruthy reports whether a decoded JSON value is truthy in JavaScript (if (value) ...).
func jsTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0 && !math.IsNaN(x)
	case json.Number:
		f, err := x.Float64()
		return err == nil && f != 0
	case int:
		return x != 0
	case int64:
		return x != 0
	}
	return true
}

// isJSObject reports whether a decoded JSON value has typeof "object" in JavaScript (objects, arrays, null).
func isJSObject(v any) bool {
	switch v.(type) {
	case nil, map[string]any, []any:
		return true
	}
	return false
}

// normalizeJSON turns any Go value into its decoded JSON form (map[string]any, []any, float64, ...), so
// Go structs passed as metadata behave like the object a client would send.
func normalizeJSON(v any) any {
	switch v.(type) {
	case nil, map[string]any, []any, string, bool, float64:
		return v
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if json.Unmarshal(raw, &out) != nil {
		return v
	}
	return out
}
