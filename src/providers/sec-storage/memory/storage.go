// Package memory provides an in-memory implementation of db.KeyValServ.
//
// It is designed for development and testing environments where a real cache
// backend (e.g., Redis) is not available. Not for use in production.
package memory

import (
	"context"
	"sync"
	"time"

	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
)

// entry holds a stored value and its optional expiry time.
type entry struct {
	value     any
	expiresAt time.Time // zero value means no expiry
}

// Store is a thread-safe, TTL-aware in-memory key-value store that satisfies
// the db.KeyValServ interface.
type Store struct {
	mu   sync.RWMutex
	data map[string]entry
}

var _ sec_storage.SecondaryStorage = (*Store)(nil)

// New creates and returns a new in-memory Store.
// It is safe for concurrent use by multiple goroutines.
func New() *Store {
	return &Store{
		data: make(map[string]entry),
	}
}

// NewSecondaryStorage creates and returns a new Store satisfying db.KeyValServ.
func NewSecondaryStorage() (sec_storage.SecondaryStorage, error) {
	return New(), nil
}

// Get retrieves the value for the given key.
// Returns (value, true, nil) if key exists and has not expired.
// Returns (nil, false, nil) when the key does not exist or has expired.
func (s *Store) Get(ctx context.Context, key string) (value any, exists bool, er error) {
	s.mu.RLock()
	e, ok := s.data[key]
	s.mu.RUnlock()

	if !ok {
		return nil, false, nil
	}
	if !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
		// Lazy eviction: remove expired entry.
		s.mu.Lock()
		delete(s.data, key)
		s.mu.Unlock()
		return nil, false, nil
	}
	return e.value, true, nil
}

// GetAndDeleteCtx atomically retrieves and deletes the value for the given key.
// Returns (value, nil) if key existed and was deleted.
// Returns (nil, nil) when the key does not exist or has expired.
func (s *Store) GetAndDeleteCtx(ctx context.Context, key string) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.data[key]
	if !ok {
		return nil, nil
	}
	delete(s.data, key)

	if !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
		return nil, nil
	}
	return e.value, nil
}

// GetAndDelete is a convenience helper for non-context callers.
func (s *Store) GetAndDelete(key string) (any, error) {
	return s.GetAndDeleteCtx(context.Background(), key)
}

// Set stores a value under the given key with an optional TTL expiration.
// An expiration of zero means the entry never expires.
func (s *Store) Set(ctx context.Context, key string, val any, expiration time.Duration) error {
	e := entry{value: val}
	if expiration > 0 {
		e.expiresAt = time.Now().Add(expiration)
	}

	s.mu.Lock()
	s.data[key] = e
	s.mu.Unlock()
	return nil
}

// Exists checks if the key exists and has not expired.
func (s *Store) Exists(ctx context.Context, key string) (bool, error) {
	s.mu.RLock()
	e, ok := s.data[key]
	s.mu.RUnlock()

	if !ok {
		return false, nil
	}
	if !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
		s.mu.Lock()
		delete(s.data, key)
		s.mu.Unlock()
		return false, nil
	}
	return true, nil
}

// Delete removes the value for the given key.
// Returns nil even when the key does not exist.
func (s *Store) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	delete(s.data, key)
	s.mu.Unlock()
	return nil
}

// Len returns the number of active entries currently held by the store.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	now := time.Now()
	for _, e := range s.data {
		if e.expiresAt.IsZero() || now.Before(e.expiresAt) {
			count++
		}
	}
	return count
}

// Flush removes all entries from the store. Useful for test teardown.
func (s *Store) Flush() {
	s.mu.Lock()
	s.data = make(map[string]entry)
	s.mu.Unlock()
}
