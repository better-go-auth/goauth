package goauth

import (
	"fmt"

	"github.com/better-go-auth/goauth/src/common/logger"
	"github.com/better-go-auth/goauth/src/providers/ratelimit"
)

// newRateLimiter builds the global rate limiter from AuthConfig.RateLimit, like better-auth's context:
// enabled ?? isProduction, window || 10s, max || 100, storage || (secondaryStorage ? "secondary-storage" :
// "memory"), customStorage over storage.
func newRateLimiter(opts GoAuthOptions) (*ratelimit.Limiter, error) {
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
			return nil, fmt.Errorf("goauth: RateLimit.Storage %q (the rateLimit table) is not supported yet; use "+
				"\"memory\", \"secondary-storage\" or RateLimit.CustomStorage", name)
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
