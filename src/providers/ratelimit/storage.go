package ratelimit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
)

// Storage names accepted by RateLimit.Storage (better-auth's rateLimit.storage).
const (
	StorageMemory           = "memory"
	StorageSecondaryStorage = "secondary-storage"
	// StorageDatabase is better-auth's "database" storage: the `rateLimit` table (id, key, count, lastRequest
	// as a bigint of Unix milliseconds), implemented by DatabaseStorage on the storage adapter. Its contract,
	// as in better-auth's createDatabaseStorageWrapper:
	//   - Get(key): the first row with key = key, nil when there is none;
	//   - Set(key, value, update=true): UPDATE rateLimit SET count, lastRequest WHERE key = key;
	//   - Set(key, value, update=false): INSERT {key, count, lastRequest};
	//   - errors never fail the request (the Limiter reports them through Options.OnError).
	StorageDatabase = "database"
)

// ─── memory ──────────────────────────────────────────────────────────────────

// MemoryStorage keeps records in process memory with an expiry of one window after the last write,
// like better-auth's memory storage. Expired records are dropped on read and by a periodic sweep.
type MemoryStorage struct {
	mu        sync.Mutex
	entries   map[string]memoryEntry
	now       func() time.Time
	lastSweep time.Time
}

type memoryEntry struct {
	rec       Record
	expiresAt time.Time
}

// sweepEvery bounds how often Set scans the map for expired entries.
const sweepEvery = time.Minute

// NewMemoryStorage returns an empty in-memory storage.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{entries: map[string]memoryEntry{}, now: time.Now}
}

// WithClock overrides the clock (tests).
func (m *MemoryStorage) WithClock(now func() time.Time) *MemoryStorage {
	m.now = now
	return m
}

// Get returns the record of key, or nil when there is none or it expired.
func (m *MemoryStorage) Get(_ context.Context, key string) (*Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	if !ok {
		return nil, nil
	}
	if !m.now().Before(e.expiresAt) {
		delete(m.entries, key)
		return nil, nil
	}
	rec := e.rec
	return &rec, nil
}

// Set stores value for one window.
func (m *MemoryStorage) Set(_ context.Context, key string, value Record, _ bool, window time.Duration) error {
	if window <= 0 {
		window = DefaultWindow
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.entries[key] = memoryEntry{rec: value, expiresAt: now.Add(window)}
	// sweep expired entries now and then so the map does not grow without bound
	if now.Sub(m.lastSweep) >= sweepEvery {
		m.lastSweep = now
		for k, e := range m.entries {
			if !now.Before(e.expiresAt) {
				delete(m.entries, k)
			}
		}
	}
	return nil
}

// Len returns the number of stored (possibly expired) records.
func (m *MemoryStorage) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

// ─── secondary storage ──────────────────────────────────────────────────────

// SecondaryStorage stores records in goauth's secondary storage exactly like better-auth's
// "secondary-storage" mode: the key is "<ip>|<path>" (no prefix), the value the JSON record
// {"key","count","lastRequest"} and the TTL one window, so a TypeScript better-auth server sharing the store
// (e.g. Redis) shares the limits.
type SecondaryStorage struct {
	store sec_storage.SecondaryStorage
}

// NewSecondaryStorage wraps a goauth secondary storage.
func NewSecondaryStorage(store sec_storage.SecondaryStorage) *SecondaryStorage {
	return &SecondaryStorage{store: store}
}

// Get reads and decodes the record of key (nil when missing or not valid JSON, like safeJSONParse).
func (s *SecondaryStorage) Get(ctx context.Context, key string) (*Record, error) {
	raw, ok, err := s.store.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if !ok || raw == nil {
		return nil, nil
	}
	var data []byte
	switch v := raw.(type) {
	case string:
		data = []byte(v)
	case []byte:
		data = v
	default:
		return nil, nil
	}
	var rec Record
	if json.Unmarshal(data, &rec) != nil {
		return nil, nil
	}
	return &rec, nil
}

// Set writes the JSON record with a TTL of one window.
func (s *SecondaryStorage) Set(ctx context.Context, key string, value Record, _ bool, window time.Duration) error {
	if window <= 0 {
		window = DefaultWindow
	}
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("ratelimit: encode record: %w", err)
	}
	return s.store.Set(ctx, key, string(data), window)
}

// ─── database ────────────────────────────────────────────────────────────────

// DatabaseStorage keeps records in better-auth's rateLimit table through a storage adapter (model
// "rateLimit" of the schema registry, which SetupGoAuth adds with RateLimit.Storage "database"). Rows
// written by a TypeScript better-auth server sharing the database are read the same way.
type DatabaseStorage struct {
	a adapter.Adapter
}

// NewDatabaseStorage returns the database storage on a. a's registry must have the rateLimit model
// (schema.Options.RateLimit).
func NewDatabaseStorage(a adapter.Adapter) *DatabaseStorage {
	return &DatabaseStorage{a: a}
}

// rateLimitModel is the logical model name of the table.
const rateLimitModel = "rateLimit"

// Get returns the record of key, nil when there is none.
func (s *DatabaseStorage) Get(ctx context.Context, key string) (*Record, error) {
	rows, err := s.a.FindMany(ctx, rateLimitModel, adapter.Query{Where: []adapter.Where{{Field: "key", Value: key}}, Limit: 1})
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	rec := &Record{Key: key}
	if n, ok := rows[0]["count"].(int64); ok {
		rec.Count = int(n)
	}
	if n, ok := rows[0]["lastRequest"].(int64); ok {
		rec.LastRequest = n
	}
	return rec, nil
}

// Set updates the row of key (update) or inserts one. An insert racing another request for the same key
// (unique violation on key) updates the row instead of losing the count.
func (s *DatabaseStorage) Set(ctx context.Context, key string, value Record, update bool, _ time.Duration) error {
	data := adapter.Record{"count": int64(value.Count), "lastRequest": value.LastRequest}
	// Step 1: a record was read before: update it
	if update {
		_, err := s.a.UpdateMany(ctx, rateLimitModel, []adapter.Where{{Field: "key", Value: key}}, data)
		return err
	}
	// Step 2: a new key: insert, or update when another request inserted it first
	data["key"] = key
	_, err := s.a.Create(ctx, rateLimitModel, data)
	if errors.Is(err, adapter.ErrUniqueViolation) {
		delete(data, "key")
		_, err = s.a.UpdateMany(ctx, rateLimitModel, []adapter.Where{{Field: "key", Value: key}}, data)
	}
	return err
}
