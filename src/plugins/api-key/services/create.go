package services

import (
	"context"
	"encoding/json"
	"time"

	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins/api-key/config"
	"github.com/better-go-auth/goauth/src/providers/access"
)

// Call describes who calls an operation: a client over HTTP (with the session of the request, if any), or
// the server (the Go API; better-auth's auth.api call without headers).
type Call struct {
	// Client is true for HTTP requests: server-only properties are rejected and a session is required.
	Client bool
	// Session is the caller's session (nil when there is none).
	Session *dtos.SessionWithUser
}

// Nullable is an optional request value that may also be null: Set reports whether it was given at all
// (JavaScript's !== undefined), Value is nil for an explicit null.
type Nullable[T any] struct {
	Set   bool
	Value *T
}

// Value returns a Nullable holding v.
func Value[T any](v T) Nullable[T] { return Nullable[T]{Set: true, Value: &v} }

// Null returns a Nullable holding an explicit null.
func Null[T any]() Nullable[T] { return Nullable[T]{Set: true} }

// CreateInput is the body of POST /api-key/create (better-auth's createApiKeyBodySchema). Pointer fields
// are optional; nil means not given.
type CreateInput struct {
	// ConfigID selects the configuration (default configuration when empty).
	ConfigID string
	// Name of the key.
	Name *string
	// ExpiresIn is the lifetime in seconds (nil = the configuration's default).
	ExpiresIn *float64
	// Prefix replaces the configuration's DefaultPrefix ([a-zA-Z0-9_-]+).
	Prefix *string
	// Remaining is the number of uses (server only; nil = unlimited).
	Remaining *int64
	// Metadata is any JSON object (EnableMetadata).
	Metadata any
	// RefillAmount / RefillInterval (ms) refill `remaining` periodically (server only, both or neither).
	RefillAmount   *int64
	RefillInterval *int64
	// RateLimitTimeWindow (ms), RateLimitMax and RateLimitEnabled override the configuration's rate limit
	// (server only).
	RateLimitTimeWindow *int64
	RateLimitMax        *int64
	RateLimitEnabled    *bool
	// Permissions of the key (server only; default: the configuration's DefaultPermissions).
	Permissions map[string][]string
	// UserID is the owner for server calls (rejected from clients).
	UserID *string
	// OrganizationID is the owner of organization-referenced keys.
	OrganizationID *string
}

// Create is better-auth's POST /api-key/create.
func (s *Service) Create(ctx context.Context, in CreateInput, call Call) (*CreateAPIKeyResponse, error) {
	// Step 1: the configuration and the caller
	opts, err := s.ResolveConfiguration(in.ConfigID)
	if err != nil {
		return nil, err
	}
	session := call.Session
	// Step 2: server-only properties and userId are not for clients
	if call.Client && (in.RefillAmount != nil || in.RefillInterval != nil || in.RateLimitMax != nil ||
		in.RateLimitTimeWindow != nil || in.RateLimitEnabled != nil || in.Permissions != nil || in.Remaining != nil) {
		return nil, ErrServerOnlyProperty
	}
	if call.Client && in.UserID != nil {
		return nil, ErrUnauthorizedSession
	}
	// Step 3: the owner (an organization, the session's user, or the server's userId)
	referenceID, err := s.createReference(ctx, in, call, opts, session)
	if err != nil {
		return nil, err
	}
	// Step 4: metadata, refill, expiry, prefix and name rules
	metadata := normalizeJSON(in.Metadata)
	if err := checkCreateValues(in, opts, metadata); err != nil {
		return nil, err
	}
	// Step 5: expired keys are cleaned up on the way (throttled)
	s.cleanupExpired(ctx)
	// Step 6: the key, its stored hash and its visible start
	prefix := opts.DefaultPrefix
	if in.Prefix != nil && *in.Prefix != "" {
		prefix = *in.Prefix
	}
	plain, err := generateKey(ctx, opts, prefix)
	if err != nil {
		return nil, err
	}
	k := s.newKeyRecord(in, opts, referenceID, plain)
	// Step 7: permissions given, or the configuration's defaults
	perms, err := s.permissionsToApply(ctx, in.Permissions, opts, referenceID)
	if err != nil {
		return nil, err
	}
	k.Permissions = perms
	if jsTruthy(metadata) {
		k.Metadata = metadata
	}
	// Step 8: store it
	stored, err := s.storeNewKey(ctx, k, opts)
	if err != nil {
		return nil, err
	}
	// Step 9: the response carries the plain key and the metadata as sent
	var respMeta any
	if in.Metadata != nil {
		respMeta = metadata
	}
	return &CreateAPIKeyResponse{APIKeyResponse: stored.Response(respMeta), Key: plain}, nil
}

// createReference returns the owner of a new key (better-auth's referenceId rules).
func (s *Service) createReference(ctx context.Context, in CreateInput, call Call, opts config.Configuration, session *dtos.SessionWithUser) (string, error) {
	sessionUserID := ""
	if session != nil {
		sessionUserID = session.User.ID
	}
	switch {
	case opts.References == config.ReferencesOrganization:
		// Step 1: organization keys need the organization and a user allowed to create its keys
		if in.OrganizationID == nil || *in.OrganizationID == "" {
			return "", ErrOrganizationIDRequired
		}
		userID := sessionUserID
		if userID == "" && in.UserID != nil {
			userID = *in.UserID
		}
		if userID == "" {
			return "", ErrUnauthorizedSession
		}
		if err := s.checkOrgPermission(ctx, userID, *in.OrganizationID, "create"); err != nil {
			return "", err
		}
		return *in.OrganizationID, nil
	case call.Client:
		// Step 2: clients create keys for themselves
		if sessionUserID == "" {
			return "", ErrUnauthorizedSession
		}
		return sessionUserID, nil
	default:
		// Step 3: the server names the user (or passes a session); both must agree
		ctxUserID := ""
		if in.UserID != nil {
			ctxUserID = *in.UserID
		}
		if sessionUserID == "" && ctxUserID == "" {
			return "", ErrUnauthorizedSession
		}
		if session != nil && ctxUserID != "" && sessionUserID != ctxUserID {
			return "", ErrUnauthorizedSession
		}
		if sessionUserID != "" {
			return sessionUserID, nil
		}
		return ctxUserID, nil
	}
}

// checkCreateValues applies better-auth's create checks in its order.
func checkCreateValues(in CreateInput, opts config.Configuration, metadata any) error {
	// Step 1: metadata must be enabled and an object
	if jsTruthy(metadata) {
		if !opts.EnableMetadata {
			return ErrMetadataDisabled
		}
		if !isJSObject(metadata) {
			return ErrInvalidMetadataType
		}
	}
	// Step 2: refillAmount and refillInterval come together
	amount := in.RefillAmount != nil && *in.RefillAmount != 0
	interval := in.RefillInterval != nil && *in.RefillInterval != 0
	if amount && !interval {
		return ErrRefillAmountAndIntervalReq
	}
	if interval && !amount {
		return ErrRefillIntervalAndAmountReq
	}
	// Step 3: custom expiry within the configured bounds (days)
	if in.ExpiresIn != nil && *in.ExpiresIn != 0 {
		if opts.KeyExpiration.DisableCustomExpiresTime {
			return ErrKeyDisabledExpiration
		}
		if err := checkExpiresInDays(*in.ExpiresIn, opts); err != nil {
			return err
		}
	}
	// Step 4: prefix and name lengths
	if in.Prefix != nil && *in.Prefix != "" {
		if n := jsLength(*in.Prefix); n < opts.MinimumPrefixLength || n > opts.MaximumPrefixLength {
			return ErrInvalidPrefixLength
		}
	}
	if in.Name != nil && *in.Name != "" {
		if n := jsLength(*in.Name); n < opts.MinimumNameLength || n > opts.MaximumNameLength {
			return ErrInvalidNameLength
		}
	} else if opts.RequireName {
		return ErrNameRequired
	}
	return nil
}

// checkExpiresInDays checks an expiresIn (seconds) against MinExpiresIn / MaxExpiresIn (days).
func checkExpiresInDays(expiresIn float64, opts config.Configuration) error {
	days := expiresIn / (3600 * 24)
	if *opts.KeyExpiration.MinExpiresIn > days {
		return ErrExpiresInTooSmall
	}
	if *opts.KeyExpiration.MaxExpiresIn < days {
		return ErrExpiresInTooLarge
	}
	return nil
}

// newKeyRecord builds the stored key of a create request (better-auth's `data`).
func (s *Service) newKeyRecord(in CreateInput, opts config.Configuration, referenceID, plain string) *APIKey {
	now := s.now()
	// Step 1: identity, owner and the visible parts of the key
	k := &APIKey{
		ConfigID:    opts.ConfigID,
		CreatedAt:   now,
		UpdatedAt:   now,
		Name:        in.Name,
		Key:         hashFor(plain, opts),
		Enabled:     true,
		ReferenceID: referenceID,
	}
	if k.ConfigID == "" {
		k.ConfigID = config.DefaultConfigID
	}
	if in.Prefix != nil {
		k.Prefix = in.Prefix
	} else if opts.DefaultPrefix != "" {
		p := opts.DefaultPrefix
		k.Prefix = &p
	}
	if *opts.StartingCharactersConfig.ShouldStore {
		start := jsSubstring(plain, opts.StartingCharactersConfig.CharactersLength)
		k.Start = &start
	}
	// Step 2: expiry (custom or the configuration's default)
	switch {
	case in.ExpiresIn != nil && *in.ExpiresIn != 0:
		t := now.Add(time.Duration(*in.ExpiresIn * float64(time.Second))).Truncate(time.Millisecond)
		k.ExpiresAt = &t
	case opts.KeyExpiration.DefaultExpiresIn > 0:
		t := now.Add(opts.KeyExpiration.DefaultExpiresIn).Truncate(time.Millisecond)
		k.ExpiresAt = &t
	}
	// Step 3: rate limit (given or the configuration's)
	k.RateLimitMax = in.RateLimitMax
	if k.RateLimitMax == nil {
		v := int64(*opts.RateLimit.MaxRequests)
		k.RateLimitMax = &v
	}
	k.RateLimitTimeWindow = in.RateLimitTimeWindow
	if k.RateLimitTimeWindow == nil {
		v := opts.RateLimit.TimeWindow.Milliseconds()
		k.RateLimitTimeWindow = &v
	}
	k.RateLimitEnabled = opts.RateLimitEnabled()
	if in.RateLimitEnabled != nil {
		k.RateLimitEnabled = *in.RateLimitEnabled
	}
	// Step 4: usage (remaining is null unless given: better-auth's body default makes the refillAmount
	// fallback unreachable)
	k.Remaining = in.Remaining
	k.RefillAmount = in.RefillAmount
	k.RefillInterval = in.RefillInterval
	return k
}

// permissionsToApply returns the JSON of the given permissions, else of the configuration's defaults.
func (s *Service) permissionsToApply(ctx context.Context, given map[string][]string, opts config.Configuration, referenceID string) (*string, error) {
	var perms map[string][]string
	switch {
	case given != nil:
		perms = given
	case opts.Permissions.DefaultPermissionsFunc != nil:
		def, err := opts.Permissions.DefaultPermissionsFunc(ctx, referenceID)
		if err != nil {
			return nil, err
		}
		perms = def
	case opts.Permissions.DefaultPermissions != nil:
		perms = opts.Permissions.DefaultPermissions
	}
	if perms == nil {
		return nil, nil
	}
	raw, err := json.Marshal(access.Statements(perms))
	if err != nil {
		return nil, err
	}
	out := string(raw)
	return &out, nil
}

// storeNewKey writes a new key where its configuration keeps keys.
func (s *Service) storeNewKey(ctx context.Context, k *APIKey, opts config.Configuration) (*APIKey, error) {
	switch {
	case opts.Storage == config.StorageSecondary && opts.FallbackToDatabase:
		// the database first (it assigns the id), then the cache
		stored, err := s.dbCreate(ctx, k)
		if err != nil {
			return nil, err
		}
		if err := s.setAPIKey(ctx, stored, opts); err != nil {
			return nil, err
		}
		return stored, nil
	case opts.Storage == config.StorageSecondary:
		k.ID = s.newID()
		if err := s.setAPIKey(ctx, k, opts); err != nil {
			return nil, err
		}
		return k, nil
	default:
		return s.dbCreate(ctx, k)
	}
}
