package services

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins/api-key/config"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

// internalError is better-auth's APIError.fromStatus("INTERNAL_SERVER_ERROR", {message}) for storage
// failures of update / delete.
func internalError(err error) error {
	return pluginkit.NewError(http.StatusInternalServerError, "INTERNAL_SERVER_ERROR", err.Error())
}

// ownedKey loads the key id for the user (better-auth's lookup in get / update / delete): it must exist in
// the lookup configuration's storage, belong to that configuration, and belong to the user (or, for
// organization keys, the user's role must allow action).
func (s *Service) ownedKey(ctx context.Context, id, configID, userID, action string) (*APIKey, config.Configuration, error) {
	// Step 1: the key, from the storage of the requested configuration
	lookup, err := s.ResolveConfiguration(configID)
	if err != nil {
		return nil, config.Configuration{}, err
	}
	k, err := s.getByID(ctx, id, lookup)
	if err != nil {
		return nil, config.Configuration{}, err
	}
	if k == nil || !config.ConfigIDMatches(k.ConfigID, lookup.ConfigID) {
		return nil, config.Configuration{}, ErrKeyNotFound
	}
	// Step 2: ownership
	opts, err := s.ResolveConfiguration(k.ConfigID)
	if err != nil {
		return nil, config.Configuration{}, err
	}
	if opts.References == config.ReferencesOrganization {
		if err := s.checkOrgPermission(ctx, userID, k.ReferenceID, action); err != nil {
			return nil, opts, err
		}
	} else if k.ReferenceID != userID {
		return nil, opts, ErrKeyNotFound
	}
	return k, opts, nil
}

// Get is better-auth's GET /api-key/get for the session's user.
func (s *Service) Get(ctx context.Context, id, configID, userID string) (*APIKeyResponse, error) {
	k, opts, err := s.ownedKey(ctx, id, configID, userID, "read")
	if err != nil {
		return nil, err
	}
	s.cleanupExpired(ctx)
	resp := k.Response(s.migrateMetadata(ctx, k, opts))
	return &resp, nil
}

// UpdateInput is the body of POST /api-key/update (better-auth's updateApiKeyBodySchema).
type UpdateInput struct {
	// ConfigID selects the configuration the key is looked up in.
	ConfigID string
	// KeyID is the id of the key.
	KeyID string
	// UserID is the owner for server calls.
	UserID *string
	Name   *string
	// Enabled enables / disables the key.
	Enabled *bool
	// Remaining sets the uses left (server only).
	Remaining *int64
	// RefillAmount / RefillInterval (ms) are server only and must come together.
	RefillAmount   *int64
	RefillInterval *int64
	// Metadata replaces the metadata (ignored unless EnableMetadata).
	Metadata Nullable[any]
	// ExpiresIn (seconds) sets a new expiry; null removes it.
	ExpiresIn Nullable[float64]
	// RateLimitEnabled, RateLimitTimeWindow (ms) and RateLimitMax are server only.
	RateLimitEnabled    *bool
	RateLimitTimeWindow *int64
	RateLimitMax        *int64
	// Permissions replaces the permissions (server only); null removes them.
	Permissions Nullable[map[string][]string]
}

// Update is better-auth's POST /api-key/update.
func (s *Service) Update(ctx context.Context, in UpdateInput, call Call) (*APIKeyResponse, error) {
	// Step 1: the user (the session's, or the server's userId) and server-only properties
	userID, err := updateUser(in, call)
	if err != nil {
		return nil, err
	}
	if call.Client && (in.RefillAmount != nil || in.RefillInterval != nil || in.RateLimitMax != nil ||
		in.RateLimitTimeWindow != nil || in.RateLimitEnabled != nil || in.Remaining != nil || in.Permissions.Set) {
		return nil, ErrServerOnlyProperty
	}
	// Step 2: the key, owned by the user
	k, opts, err := s.ownedKey(ctx, in.KeyID, in.ConfigID, userID, "update")
	if err != nil {
		return nil, err
	}
	// Step 3: the new values, checked like better-auth
	values, err := s.updateValues(in, opts)
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, ErrNoValuesToUpdate
	}
	// Step 4: write them where the key lives
	updated, err := s.writeUpdate(ctx, k, values, opts)
	if err != nil {
		return nil, internalError(err)
	}
	s.cleanupExpired(ctx)
	resp := updated.Response(s.migrateMetadata(ctx, updated, opts))
	return &resp, nil
}

// updateUser returns the user an update acts for (better-auth: a client needs a session; the server
// passes userId, which must match a session it also passes).
func updateUser(in UpdateInput, call Call) (string, error) {
	var userID string
	switch {
	case call.Session != nil:
		userID = call.Session.User.ID
	case call.Client:
		return "", ErrUnauthorizedSession
	case in.UserID != nil:
		userID = *in.UserID
	}
	if userID == "" {
		return "", ErrUnauthorizedSession
	}
	if call.Session != nil && in.UserID != nil && *in.UserID != "" && *in.UserID != call.Session.User.ID {
		return "", ErrUnauthorizedSession
	}
	return userID, nil
}

// updateValues builds the changed fields of an update (better-auth's newValues), with its checks in order.
func (s *Service) updateValues(in UpdateInput, opts config.Configuration) (adapter.Record, error) {
	values := adapter.Record{}
	// Step 1: name and enabled flag
	if in.Name != nil {
		if n := jsLength(*in.Name); n < opts.MinimumNameLength || n > opts.MaximumNameLength {
			return nil, ErrInvalidNameLength
		}
		values[FieldName] = *in.Name
	}
	if in.Enabled != nil {
		values[FieldEnabled] = *in.Enabled
	}
	// Step 2: expiry (null removes it)
	if in.ExpiresIn.Set {
		if opts.KeyExpiration.DisableCustomExpiresTime {
			return nil, ErrKeyDisabledExpiration
		}
		if in.ExpiresIn.Value != nil {
			if err := checkExpiresInDays(*in.ExpiresIn.Value, opts); err != nil {
				return nil, err
			}
		}
		if in.ExpiresIn.Value != nil && *in.ExpiresIn.Value != 0 {
			values[FieldExpiresAt] = s.now().Add(time.Duration(*in.ExpiresIn.Value * float64(time.Second))).Truncate(time.Millisecond)
		} else {
			values[FieldExpiresAt] = nil
		}
	}
	// Step 3: metadata (only with EnableMetadata; silently ignored otherwise)
	if in.Metadata.Set && opts.EnableMetadata {
		var md any
		if in.Metadata.Value != nil {
			md = normalizeJSON(*in.Metadata.Value)
		}
		if !isJSObject(md) {
			return nil, ErrInvalidMetadataType
		}
		values[FieldMetadata] = encodeMetadataColumn(md)
	}
	// Step 4: usage and refill
	if in.Remaining != nil {
		values[FieldRemaining] = float64(*in.Remaining)
	}
	if in.RefillAmount != nil || in.RefillInterval != nil {
		if in.RefillAmount != nil && in.RefillInterval == nil {
			return nil, ErrRefillAmountAndIntervalReq
		}
		if in.RefillInterval != nil && in.RefillAmount == nil {
			return nil, ErrRefillIntervalAndAmountReq
		}
		values[FieldRefillAmount] = float64(*in.RefillAmount)
		values[FieldRefillInterval] = float64(*in.RefillInterval)
	}
	// Step 5: rate limit and permissions
	if in.RateLimitEnabled != nil {
		values[FieldRateLimitEnabled] = *in.RateLimitEnabled
	}
	if in.RateLimitTimeWindow != nil {
		values[FieldRateLimitTimeWindow] = float64(*in.RateLimitTimeWindow)
	}
	if in.RateLimitMax != nil {
		values[FieldRateLimitMax] = float64(*in.RateLimitMax)
	}
	if in.Permissions.Set {
		if in.Permissions.Value == nil {
			values[FieldPermissions] = nil
		} else {
			raw, err := json.Marshal(*in.Permissions.Value)
			if err != nil {
				return nil, err
			}
			values[FieldPermissions] = string(raw)
		}
	}
	return values, nil
}

// writeUpdate applies update values to a key in its storage and returns the updated key.
func (s *Service) writeUpdate(ctx context.Context, k *APIKey, values adapter.Record, opts config.Configuration) (*APIKey, error) {
	switch {
	case opts.Storage == config.StorageSecondary && opts.FallbackToDatabase:
		stored, err := s.dbUpdate(ctx, k.ID, values)
		if err != nil {
			return nil, err
		}
		if stored == nil {
			return k, nil
		}
		if err := s.setAPIKey(ctx, stored, opts); err != nil {
			return nil, err
		}
		return stored, nil
	case opts.Storage == config.StorageDatabase:
		stored, err := s.dbUpdate(ctx, k.ID, values)
		if err != nil {
			return nil, err
		}
		if stored == nil {
			return k, nil
		}
		return stored, nil
	default:
		// the stored copy with the new values and a new updatedAt
		updated := applyValues(*k, values)
		updated.UpdatedAt = s.now()
		if err := s.setAPIKey(ctx, &updated, opts); err != nil {
			return nil, err
		}
		return &updated, nil
	}
}

// applyValues returns k with update values applied (secondary-storage keys).
func applyValues(k APIKey, values adapter.Record) APIKey {
	// the record round trip keeps the column encodings (metadata JSON, numbers) in one place
	rec := k.record()
	rec[FieldID] = k.ID
	for f, v := range values {
		rec[f] = v
	}
	out := fromRecord(rec)
	return *out
}

// Delete is better-auth's POST /api-key/delete for the session's user.
func (s *Service) Delete(ctx context.Context, keyID, configID string, user *dtos.UserResponse) error {
	// Step 1: banned users cannot delete keys
	if user == nil || user.ID == "" {
		return ErrUnauthorizedSession
	}
	if user.Banned {
		return ErrUserBanned
	}
	// Step 2: the key, owned by the user
	k, opts, err := s.ownedKey(ctx, keyID, configID, user.ID, "delete")
	if err != nil {
		return err
	}
	// Step 3: remove it from its storage
	if err := s.removeKey(ctx, k, opts); err != nil {
		return internalError(err)
	}
	s.cleanupExpired(ctx)
	return nil
}

// ListInput is the query of GET /api-key/list.
type ListInput struct {
	// ConfigID lists only keys of this configuration (all configurations when empty).
	ConfigID string
	// OrganizationID lists the organization's keys instead of the user's.
	OrganizationID string
	// Limit / Offset paginate (nil = all).
	Limit  *int
	Offset *int
	// SortBy is a field name (e.g. "createdAt", "name"); SortDirection "asc" (default) or "desc".
	SortBy        string
	SortDirection string
}

// ListResult is the body of GET /api-key/list.
type ListResult struct {
	APIKeys []APIKeyResponse `json:"apiKeys"`
	Total   int              `json:"total"`
	Limit   *int             `json:"limit,omitempty"`
	Offset  *int             `json:"offset,omitempty"`
}

// List is better-auth's GET /api-key/list for the session's user (or an organization the user may read).
func (s *Service) List(ctx context.Context, in ListInput, userID string) (*ListResult, error) {
	// Step 1: whose keys
	if in.OrganizationID != "" {
		if err := s.checkOrgPermission(ctx, userID, in.OrganizationID, "read"); err != nil {
			return nil, err
		}
	}
	referenceID, expected := userID, config.ReferencesUser
	if in.OrganizationID != "" {
		referenceID, expected = in.OrganizationID, config.ReferencesOrganization
	}
	var sortBy *sortSpec
	if in.SortBy != "" {
		sortBy = &sortSpec{Field: in.SortBy, Desc: in.SortDirection == "desc"}
	}
	// Step 2: read every storage once (one configuration, or one per storage backend)
	all, err := s.listAll(ctx, in.ConfigID, referenceID, sortBy)
	if err != nil {
		return nil, err
	}
	// Step 3: keep keys whose configuration has the expected owner type (and the requested configuration)
	filtered := make([]*APIKey, 0, len(all))
	for _, k := range all {
		refs := config.ReferencesUser
		if c, ok := s.configForKey(k.ConfigID); ok {
			refs = c.References
		}
		if refs != expected || k.ReferenceID != referenceID {
			continue
		}
		if in.ConfigID != "" && !config.ConfigIDMatches(k.ConfigID, in.ConfigID) {
			continue
		}
		filtered = append(filtered, k)
	}
	// Step 4: paginate in memory
	total := len(filtered)
	page := filtered
	if in.Offset != nil {
		page = page[min(*in.Offset, len(page)):]
	}
	if in.Limit != nil {
		page = page[:min(*in.Limit, len(page))]
	}
	s.cleanupExpired(ctx)
	// Step 5: the response (metadata decoded), then migrate legacy metadata of database keys
	out := &ListResult{APIKeys: make([]APIKeyResponse, 0, len(page)), Total: total, Limit: in.Limit, Offset: in.Offset}
	for _, k := range page {
		out.APIKeys = append(out.APIKeys, k.Response(ParseMetadata(k.Metadata)))
	}
	if err := s.migrateListMetadata(ctx, page); err != nil {
		return nil, err
	}
	return out, nil
}

// listAll returns the owner's keys from the storages to read, without duplicates.
func (s *Service) listAll(ctx context.Context, configID, referenceID string, sortBy *sortSpec) ([]*APIKey, error) {
	// Step 1: one configuration
	if configID != "" {
		opts, err := s.ResolveConfiguration(configID)
		if err != nil {
			return nil, err
		}
		return s.listByReference(ctx, referenceID, opts, sortBy)
	}
	// Step 2: the first configuration of every storage backend
	seenBackend := map[string]bool{}
	seenKey := map[string]bool{}
	var all []*APIKey
	for _, c := range s.configs {
		id := storageIdentifier(c)
		if seenBackend[id] {
			continue
		}
		seenBackend[id] = true
		keys, err := s.listByReference(ctx, referenceID, c, sortBy)
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			if !seenKey[k.ID] {
				seenKey[k.ID] = true
				all = append(all, k)
			}
		}
	}
	return all, nil
}

// migrateListMetadata is better-auth's batchMigrateLegacyMetadata, run through the background-task handler
// when one is configured (runInBackgroundOrAwait).
func (s *Service) migrateListMetadata(ctx context.Context, keys []*APIKey) error {
	// Step 1: only with a configuration that uses the database
	var dbConfig *config.Configuration
	for i := range s.configs {
		if s.configs[i].Storage == config.StorageDatabase || s.configs[i].FallbackToDatabase {
			dbConfig = &s.configs[i]
			break
		}
	}
	if dbConfig == nil {
		return nil
	}
	var legacy []*APIKey
	for _, k := range keys {
		if needsMetadataMigration(k.Metadata) {
			legacy = append(legacy, k)
		}
	}
	if len(legacy) == 0 {
		return nil
	}
	// Step 2: rewrite them (failures are logged per key)
	return s.conf.RunInBackgroundOrAwait(ctx, func(ctx context.Context) error {
		for _, k := range legacy {
			s.migrateMetadata(ctx, k, *dbConfig)
		}
		return nil
	})
}
