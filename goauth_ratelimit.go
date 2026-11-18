package goauth

import (
	"fmt"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/common/logger"
	"github.com/better-go-auth/goauth/src/providers/ratelimit"
)

// newRateLimiter builds the global rate limiter from AuthConfig.RateLimit, like better-auth's context:
// enabled ?? isProduction, window || 10s, max || 100, storage || (secondaryStorage ? "secondary-storage" :
// "memory"), customStorage over storage. "database" uses the rateLimit table through store.
func newRateLimiter(opts GoAuthOptions, store adapter.Adapter) (*ratelimit.Limiter, error) {
	rl := opts.RateLimit
	// Step 1: pick the record storage
	storage := rl.CustomStorage
	if storage == nil {
		name := rl.Storage
		if name == "" {
			name = ratelimit.StorageMemory
			if opts.SecondaryStorage != nil {
				name = ratelimit.StorageSecondaryStorage
			}
		}
		switch name {
		case ratelimit.StorageMemory:
			storage = ratelimit.NewMemoryStorage()
		case ratelimit.StorageSecondaryStorage:
			if opts.SecondaryStorage == nil {
				return nil, fmt.Errorf("goauth: RateLimit.Storage %q needs GoAuthOptions.SecondaryStorage", name)
			}
			storage = ratelimit.NewSecondaryStorage(opts.SecondaryStorage)
		case ratelimit.StorageDatabase:
			// the rateLimit model is in the registry (SchemaOptions) and created by the migrator
			if store == nil {
				return nil, fmt.Errorf("goauth: RateLimit.Storage %q needs GoAuthOptions.Conn or adapter-based Repositories", name)
			}
			storage = ratelimit.NewDatabaseStorage(store)
		default:
			return nil, fmt.Errorf("goauth: unknown RateLimit.Storage %q", name)
		}
	}
	// Step 2: the limiter; storage failures are logged and never fail a request (better-auth)
	return ratelimit.New(ratelimit.Options{
		Enabled:     rl.IsEnabled(),
		Global:      ratelimit.Rule{Window: rl.Window, Max: rl.Max},
		CustomRules: rl.CustomRules,
		Storage:     storage,
		BasePath:    opts.BasePath,
		OnError:     func(err error) { logger.Error("Error setting rate limit", "err", err) },
	}), nil
}
