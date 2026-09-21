package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
	"github.com/redis/go-redis/v9"
)

// TODO: may be just improt the redis grom go cmn
type Config struct {
	Host     string
	Port     string
	Password string
	Username string
	DB       int
}

type RedisStorage struct {
	client *redis.Client
}

var _ sec_storage.SecondaryStorage = (*RedisStorage)(nil)

func NewRedisStorage(cfg *Config) (*RedisStorage, error) {
	addr := fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: cfg.Password,
		Username: cfg.Username,
		DB:       cfg.DB,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis: ping failed: %w", err)
	}

	return &RedisStorage{client: client}, nil
}

func (r *RedisStorage) Client() *redis.Client {
	return r.client
}

func (r *RedisStorage) Get(ctx context.Context, key string) (any, bool, error) {
	val, err := r.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return val, true, nil
}

func (r *RedisStorage) GetAndDeleteCtx(ctx context.Context, key string) (any, error) {
	val, err := r.client.GetDel(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	return val, err
}

func (r *RedisStorage) Set(ctx context.Context, key string, val any, expiration time.Duration) error {
	return r.client.Set(ctx, key, val, expiration).Err()
}

func (r *RedisStorage) Exists(ctx context.Context, key string) (bool, error) {
	n, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (r *RedisStorage) Delete(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}
