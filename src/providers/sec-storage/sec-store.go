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
