package sec_storage

import (
	"context"
	"time"
)

type SecondaryStorage interface {
	Get(ctx context.Context, key string) (value any, exists bool, er error)
	GetAndDeleteCtx(ctx context.Context, key string) (any, error)
	Set(ctx context.Context, key string, val any, expiration time.Duration) error
	Exists(ctx context.Context, key string) (bool, error)
	Delete(ctx context.Context, key string) error
}

// UpdateFunc computes the next value of a key from its current value. It may be called more than once
// (optimistic retries), so it must not have side effects. remove=true deletes the key; ttl <= 0 keeps no
// expiry.
type UpdateFunc func(current any, exists bool) (next any, ttl time.Duration, remove bool)

// AtomicUpdater is an optional SecondaryStorage capability: a read-modify-write of one key that no other
// writer (in this or another process) can interleave with. The session manager uses it for better-auth's
// "active-sessions-<userId>" index; stores without it fall back to an in-process lock.
type AtomicUpdater interface {
	Update(ctx context.Context, key string, fn UpdateFunc) error
}
