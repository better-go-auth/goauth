package ratelimit

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
)

// Storage names accepted by RateLimit.Storage (better-auth's rateLimit.storage).
const (
	StorageMemory           = "memory"
	StorageSecondaryStorage = "secondary-storage"
	// StorageDatabase is better-auth's "database" storage: the `rateLimit` table (id, key, count, lastRequest
	// as a bigint of Unix milliseconds). SetupGoAuth rejects it until a Storage for that table exists
	// (task 3.2). Its contract, as in better-auth's createDatabaseStorageWrapper:
	//   - Get(key): the first row with key = key, nil when there is none;
	//   - Set(key, value, update=true): UPDATE rateLimit SET count, lastRequest WHERE key = key;
	//   - Set(key, value, update=false): INSERT {key, count, lastRequest};
	//   - errors never fail the request (the Limiter reports them through Options.OnError).
	// Any Storage with these semantics can already be passed as AuthConfig.RateLimit.CustomStorage.
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
