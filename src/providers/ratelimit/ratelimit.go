// Package ratelimit implements better-auth's fixed-window rate limiter: requests are counted per
// "<client ip>|<path>" key inside a window, stored in secondary storage when configured or in memory.
package ratelimit

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"time"

	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
)

// Rule limits a path to Max requests per Window (better-auth's { window, max }).
type Rule struct {
	Window time.Duration
	Max    int
}

// Valid reports whether the rule limits anything.
func (r Rule) Valid() bool { return r.Window > 0 && r.Max > 0 }

// bucket is one window's counter, stored as JSON so every storage backend can hold it.
type bucket struct {
	Count       int   `json:"count"`
	LastRequest int64 `json:"lastRequest"` // unix ms of the window start
}

// Limiter counts requests per key.
type Limiter struct {
	store sec_storage.SecondaryStorage
	now   func() time.Time

	mu  sync.Mutex
	mem map[string]bucket
}

// New returns a limiter that uses store when it is non-nil and process memory otherwise.
func New(store sec_storage.SecondaryStorage) *Limiter {
	return &Limiter{store: store, now: time.Now, mem: map[string]bucket{}}
}

// WithClock overrides the clock (tests).
func (l *Limiter) WithClock(now func() time.Time) *Limiter {
	l.now = now
	return l
}

// Allow records one request for key under rule. It reports whether the request may proceed and,
// when it may not, how many seconds the client should wait (better-auth's X-Retry-After).
func (l *Limiter) Allow(ctx context.Context, key string, rule Rule) (bool, int) {
	if l == nil || !rule.Valid() {
		return true, 0
	}
	// Step 1: serialise read-modify-write on the counter (single process; shared storage is best effort)
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now().UnixMilli()
	windowMs := rule.Window.Milliseconds()
	storeKey := "rate-limit:" + key

	// Step 2: load the current window
	b, found := l.load(ctx, storeKey)

	// Step 3: a new window starts when there is none or the old one is over
	if !found || now-b.LastRequest > windowMs {
		b = bucket{Count: 1, LastRequest: now}
		l.save(ctx, storeKey, b, rule.Window)
		return true, 0
	}

	// Step 4: inside the window: refuse once the budget is spent
	if b.Count >= rule.Max {
		retry := int((b.LastRequest + windowMs - now + 999) / 1000)
		if retry < 1 {
			retry = 1
		}
		return false, retry
	}
	b.Count++
	l.save(ctx, storeKey, b, time.Duration(b.LastRequest+windowMs-now)*time.Millisecond)
	return true, 0
}

func (l *Limiter) load(ctx context.Context, key string) (bucket, bool) {
	var b bucket
	if l.store == nil {
		b, ok := l.mem[key]
		return b, ok
	}
	raw, ok, err := l.store.Get(ctx, key)
	if err != nil || !ok || raw == nil {
		return b, false
	}
	var data []byte
	switch v := raw.(type) {
	case string:
		data = []byte(v)
	case []byte:
		data = v
	default:
		return b, false
	}
	if json.Unmarshal(data, &b) != nil {
		return b, false
	}
	return b, true
}

func (l *Limiter) save(ctx context.Context, key string, b bucket, ttl time.Duration) {
	if ttl <= 0 {
		ttl = time.Second
	}
	if l.store == nil {
		l.mem[key] = b
		// drop expired windows now and then so the map does not grow without bound
		if len(l.mem) > 10000 {
			now := l.now().UnixMilli()
			for k, v := range l.mem {
				if now-v.LastRequest > 24*time.Hour.Milliseconds() {
					delete(l.mem, k)
				}
			}
		}
		return
	}
	data, _ := json.Marshal(b)
	_ = l.store.Set(ctx, key, string(data), ttl)
}

// RetryAfterHeader formats seconds for the X-Retry-After header.
func RetryAfterHeader(seconds int) string { return strconv.Itoa(seconds) }
