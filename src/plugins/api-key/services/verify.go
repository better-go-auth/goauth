package services

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/logger"
	"github.com/better-go-auth/goauth/src/plugins/api-key/config"
	"github.com/better-go-auth/goauth/src/providers/access"
)

// rateLimitResult is better-auth's isRateLimited result.
type rateLimitResult struct {
	success    bool
	tryAgainIn int64
	// lastRequest / requestCount are the updates to write (nil = unchanged)
	lastRequest  *time.Time
	requestCount *int64
}

// isRateLimited is better-auth's isRateLimited: a fixed window per key that starts at the first request
// after the previous window ended.
func isRateLimited(k *APIKey, opts config.Configuration, now time.Time) rateLimitResult {
	one := int64(1)
	// Step 1: rate limiting off for the configuration or the key: only record the request time
	if !opts.RateLimitEnabled() || !k.RateLimitEnabled {
		return rateLimitResult{success: true, lastRequest: &now}
	}
	// Step 2: no limit configured on the key: nothing to record
	if k.RateLimitTimeWindow == nil || k.RateLimitMax == nil {
		return rateLimitResult{success: true}
	}
	// Step 3: the first request, or the previous window is over: a new window
	if k.LastRequest == nil {
		return rateLimitResult{success: true, lastRequest: &now, requestCount: &one}
	}
	since := now.Sub(*k.LastRequest).Milliseconds()
	if since > *k.RateLimitTimeWindow {
		return rateLimitResult{success: true, lastRequest: &now, requestCount: &one}
	}
	// Step 4: the window is full
	if k.RequestCount >= *k.RateLimitMax {
		return rateLimitResult{success: false, tryAgainIn: int64(math.Ceil(float64(*k.RateLimitTimeWindow - since)))}
	}
	// Step 5: count the request
	next := k.RequestCount + 1
	return rateLimitResult{success: true, lastRequest: &now, requestCount: &next}
}

// validateRequest is a key validation (better-auth's validateApiKey arguments).
type validateRequest struct {
	key         string
	lookup      config.Configuration
	permissions map[string][]string
	// expectedConfigID, when set, must match the key's configId
	expectedConfigID *string
	// runCustomValidator runs the key configuration's CustomAPIKeyValidator
	runCustomValidator bool
}

// validate is better-auth's validateApiKey: it checks the key (existence, configuration, custom validator,
// enabled, expiry, permissions, usage, rate limit), records the use and returns the updated key and its
// configuration.
func (s *Service) validate(ctx context.Context, req validateRequest) (*APIKey, config.Configuration, error) {
	// Step 1: find the key by its stored form
	hashed := hashFor(req.key, req.lookup)
	k, err := s.getByHashedKey(ctx, hashed, req.lookup)
	if err != nil {
		return nil, config.Configuration{}, err
	}
	if k == nil {
		return nil, config.Configuration{}, ErrInvalidAPIKey
	}
	if req.expectedConfigID != nil && !config.ConfigIDMatches(k.ConfigID, *req.expectedConfigID) {
		return nil, config.Configuration{}, ErrInvalidAPIKey
	}
	opts, err := s.ResolveConfiguration(k.ConfigID)
	if err != nil {
		return nil, config.Configuration{}, err
	}
	// Step 2: the custom validator, enabled flag and expiry
	if req.runCustomValidator && opts.CustomAPIKeyValidator != nil {
		ok, err := opts.CustomAPIKeyValidator(ctx, req.key)
		if err != nil {
			return nil, opts, err
		}
		if !ok {
			return nil, opts, ErrKeyNotFound.WithStatus(401)
		}
	}
	if !k.Enabled {
		return nil, opts, ErrKeyDisabled
	}
	now := s.now()
	if k.ExpiresAt != nil && now.After(*k.ExpiresAt) {
		if err := s.removeMaybeDeferred(ctx, k, opts); err != nil {
			return nil, opts, err
		}
		return nil, opts, ErrKeyExpired
	}
	// Step 3: the requested permissions must be granted by the key's
	if req.permissions != nil {
		granted := k.ParsedPermissions()
		if granted == nil {
			return nil, opts, ErrKeyNotFound.WithStatus(401)
		}
		if !access.NewRole(access.Statements(granted)).Authorize(access.Req(req.permissions)).Success {
			return nil, opts, ErrKeyNotFound.WithStatus(401)
		}
	}
	// Step 4: usage: an exhausted key without refill is deleted; otherwise refill when due and count the use
	remaining, lastRefillAt := k.Remaining, k.LastRefillAt
	if k.Remaining != nil && *k.Remaining == 0 && k.RefillAmount == nil {
		if err := s.removeMaybeDeferred(ctx, k, opts); err != nil {
			return nil, opts, err
		}
		return nil, opts, ErrUsageExceeded
	} else if remaining != nil {
		r := *remaining
		last := k.CreatedAt
		if lastRefillAt != nil {
			last = *lastRefillAt
		}
		if k.RefillInterval != nil && *k.RefillInterval != 0 && k.RefillAmount != nil && *k.RefillAmount != 0 {
			if now.Sub(last).Milliseconds() > *k.RefillInterval {
				r = *k.RefillAmount
				t := now
				lastRefillAt = &t
			}
		}
		if r == 0 {
			return nil, opts, ErrUsageExceeded
		}
		r--
		remaining = &r
	}
	// Step 5: the key's rate limit
	rl := isRateLimited(k, opts, now)
	if !rl.success {
		return nil, opts, &RateLimitedError{TryAgainIn: rl.tryAgainIn}
	}
	// Step 6: record the use (remaining, refill time, rate-limit counters, updatedAt)
	mutations := adapter.Record{
		FieldRemaining:    numValue(remaining),
		FieldLastRefillAt: timeValue(lastRefillAt),
		FieldUpdatedAt:    now,
	}
	updated := *k
	updated.Remaining, updated.LastRefillAt, updated.UpdatedAt = remaining, lastRefillAt, now
	if rl.lastRequest != nil {
		mutations[FieldLastRequest] = *rl.lastRequest
		updated.LastRequest = rl.lastRequest
	}
	if rl.requestCount != nil {
		mutations[FieldRequestCount] = float64(*rl.requestCount)
		updated.RequestCount = *rl.requestCount
	}
	perform := func(ctx context.Context) (*APIKey, error) {
		return s.applyUsage(ctx, k, hashed, &updated, mutations, opts)
	}
	// Step 7: deferred (optimistic answer) or now
	if opts.DeferUpdates {
		s.runInBackground(ctx, "Failed to update API key:", func(ctx context.Context) error {
			_, err := perform(ctx)
			return err
		})
		return &updated, opts, nil
	}
	stored, err := perform(ctx)
	if err != nil {
		return nil, opts, err
	}
	if stored == nil {
		return nil, opts, ErrFailedToUpdateAPIKey
	}
	return stored, opts, nil
}

// applyUsage writes the usage mutations of a validated key to its storage and returns the stored key.
func (s *Service) applyUsage(ctx context.Context, k *APIKey, hashed string, updated *APIKey, mutations adapter.Record, opts config.Configuration) (*APIKey, error) {
	switch {
	case opts.Storage == config.StorageDatabase:
		return s.dbUpdate(ctx, k.ID, mutations)
	case opts.FallbackToDatabase:
		stored, err := s.dbUpdate(ctx, k.ID, mutations)
		if err != nil || stored == nil {
			return stored, err
		}
		if err := s.setAPIKey(ctx, stored, opts); err != nil {
			return nil, err
		}
		return stored, nil
	default:
		// the storage copy may have changed meanwhile: merge the mutations into the fresh one
		fresh, err := s.getByHashedKey(ctx, hashed, opts)
		if err != nil || fresh == nil {
			return nil, err
		}
		merged := *fresh
		merged.Remaining, merged.LastRefillAt, merged.UpdatedAt = updated.Remaining, updated.LastRefillAt, updated.UpdatedAt
		if _, ok := mutations[FieldLastRequest]; ok {
			merged.LastRequest = updated.LastRequest
		}
		if _, ok := mutations[FieldRequestCount]; ok {
			merged.RequestCount = updated.RequestCount
		}
		if err := s.setAPIKey(ctx, &merged, opts); err != nil {
			return nil, err
		}
		return &merged, nil
	}
}

// removeMaybeDeferred deletes an expired or exhausted key, in the background with DeferUpdates.
func (s *Service) removeMaybeDeferred(ctx context.Context, k *APIKey, opts config.Configuration) error {
	if opts.DeferUpdates {
		s.runInBackground(ctx, "Deferred update failed:", func(ctx context.Context) error { return s.removeKey(ctx, k, opts) })
		return nil
	}
	return s.removeKey(ctx, k, opts)
}

// VerifyInput is the body of better-auth's server-only verifyApiKey.
type VerifyInput struct {
	// Key is the plain API key.
	Key string
	// Permissions the key must grant ({resource: [actions]}).
	Permissions map[string][]string
	// ConfigID, when set, scopes the verification to that configuration (and runs its custom validator
	// first); otherwise the key is checked against its own configuration.
	ConfigID *string
}

// VerifyError is the error of a failed verification ({code, message} and, for RATE_LIMITED,
// details.tryAgainIn).
type VerifyError struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

// VerifyResult is better-auth's verifyApiKey response: {valid, error, key}.
type VerifyResult struct {
	Valid bool            `json:"valid"`
	Error *VerifyError    `json:"error"`
	Key   *APIKeyResponse `json:"key"`
}

// Verify is better-auth's verifyApiKey (server only). It returns an error only when the configuration
// cannot be resolved; an invalid key is a result with Valid false.
func (s *Service) Verify(ctx context.Context, in VerifyInput) (*VerifyResult, error) {
	// Step 1: the lookup configuration (a failure here is thrown, like better-auth)
	configID := ""
	if in.ConfigID != nil {
		configID = *in.ConfigID
	}
	lookup, err := s.ResolveConfiguration(configID)
	if err != nil {
		return nil, err
	}
	// Step 2: a scoped verification runs the configuration's validator first
	if in.ConfigID != nil && lookup.CustomAPIKeyValidator != nil {
		ok, err := lookup.CustomAPIKeyValidator(ctx, in.Key)
		if err != nil {
			return nil, err
		}
		if !ok {
			return &VerifyResult{Error: &VerifyError{Code: "KEY_NOT_FOUND", Message: ErrorCodes["INVALID_API_KEY"]}}, nil
		}
	}
	// Step 3: validate (errors become {valid: false, error})
	k, opts, err := s.validate(ctx, validateRequest{
		key: in.Key, lookup: lookup, permissions: in.Permissions,
		expectedConfigID: in.ConfigID, runCustomValidator: in.ConfigID == nil,
	})
	if err != nil {
		logger.Error("Failed to validate API key:", "err", err)
		return &VerifyResult{Error: verifyError(err)}, nil
	}
	if opts.DeferUpdates {
		s.runInBackground(ctx, "Failed to delete expired API keys:", func(ctx context.Context) error {
			return s.DeleteAllExpired(ctx, false)
		})
	}
	// Step 4: the key without its hash, metadata decoded
	resp := k.Response(s.migrateMetadata(ctx, k, opts))
	return &VerifyResult{Valid: true, Key: &resp}, nil
}

// verifyError converts a validation error to the verify response's error.
func verifyError(err error) *VerifyError {
	var rl *RateLimitedError
	if errors.As(err, &rl) {
		body := rl.Body()
		return &VerifyError{Code: RateLimitedCode, Message: body["message"].(string), Details: body["details"].(map[string]any)}
	}
	if ae := autherr.AsAuthError(err); ae != nil {
		return &VerifyError{Code: string(ae.Code), Message: ae.Message}
	}
	return &VerifyError{Code: "INVALID_API_KEY", Message: ErrorCodes["INVALID_API_KEY"]}
}

// DeleteAllExpiredResult is the result of better-auth's server-only deleteAllExpiredApiKeys endpoint.
type DeleteAllExpiredResult struct {
	Success bool
	Error   error
}

// DeleteAllExpiredNow is better-auth's deleteAllExpiredApiKeys endpoint: the cleanup without throttle.
func (s *Service) DeleteAllExpiredNow(ctx context.Context) DeleteAllExpiredResult {
	if err := s.DeleteAllExpired(ctx, true); err != nil {
		logger.Error("[API KEY PLUGIN] Failed to delete expired API keys:", "err", err)
		return DeleteAllExpiredResult{Error: err}
	}
	return DeleteAllExpiredResult{Success: true}
}
