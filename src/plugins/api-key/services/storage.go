package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/common/logger"
	"github.com/better-go-auth/goauth/src/plugins/api-key/config"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
)

// storageConcurrency bounds parallel secondary-storage reads (better-auth's STORAGE_CONCURRENCY).
const storageConcurrency = 10

// errSecondaryStorageRequired is better-auth's error when storage is "secondary-storage" without a store.
var errSecondaryStorageRequired = errors.New("Secondary storage is required when storage mode is 'secondary-storage'")

// Storage keys (better-auth's getStorageKeyByHashedKey / ById / ByReferenceId).
func storageKeyByHashedKey(hashed string) string { return "api-key:" + hashed }
func storageKeyByID(id string) string            { return "api-key:by-id:" + id }
func storageKeyByReferenceID(ref string) string  { return "api-key:by-ref:" + ref }

// kv is the key-value store of one configuration: its CustomStorage or goauth's secondary storage.
type kv interface {
	get(ctx context.Context, key string) (string, bool, error)
	set(ctx context.Context, key, value string, ttl time.Duration) error
	del(ctx context.Context, key string) error
}

// secondaryKV adapts goauth's SecondaryStorage.
type secondaryKV struct{ s sec_storage.SecondaryStorage }

func (k secondaryKV) get(ctx context.Context, key string) (string, bool, error) {
	v, ok, err := k.s.Get(ctx, key)
	if err != nil || !ok || v == nil {
		return "", false, err
	}
	switch x := v.(type) {
	case string:
		return x, true, nil
	case []byte:
		return string(x), true, nil
	default:
		// a store that decoded the JSON: encode it again
		raw, err := json.Marshal(x)
		if err != nil {
			return "", false, err
		}
		return string(raw), true, nil
	}
}

func (k secondaryKV) set(ctx context.Context, key, value string, ttl time.Duration) error {
	return k.s.Set(ctx, key, value, ttl)
}

func (k secondaryKV) del(ctx context.Context, key string) error { return k.s.Delete(ctx, key) }

// customKV adapts Configuration.CustomStorage.
type customKV struct{ s config.KeyStorage }

func (k customKV) get(ctx context.Context, key string) (string, bool, error) {
	return k.s.Get(ctx, key)
}
func (k customKV) set(ctx context.Context, key, value string, ttl time.Duration) error {
	return k.s.Set(ctx, key, value, ttl)
}
func (k customKV) del(ctx context.Context, key string) error { return k.s.Delete(ctx, key) }

// storageFor returns the store of a configuration (custom storage first), or nil.
func (s *Service) storageFor(opts config.Configuration) kv {
	if opts.CustomStorage != nil {
		return customKV{opts.CustomStorage}
	}
	if s.store != nil {
		return secondaryKV{s.store}
	}
	return nil
}

// ttlFor is better-auth's calculateTTL: whole seconds until the key expires, 0 (no expiry) otherwise.
func (s *Service) ttlFor(k *APIKey) time.Duration {
	if k.ExpiresAt == nil {
		return 0
	}
	secs := int64(k.ExpiresAt.Sub(s.now()) / time.Second)
	if secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return 0
}

// ─── Database ────────────────────────────────────────────────────────────────

// dbFindOne returns the key whose field equals value, or nil.
func (s *Service) dbFindOne(ctx context.Context, field, value string) (*APIKey, error) {
	if s.adapter == nil {
		return nil, errors.New("api-key: no database adapter")
	}
	rec, err := s.adapter.FindOne(ctx, ModelName, []adapter.Where{{Field: field, Value: value}})
	if errors.Is(err, adapter.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return fromRecord(rec), nil
}

// dbCreate inserts k and returns the stored key.
func (s *Service) dbCreate(ctx context.Context, k *APIKey) (*APIKey, error) {
	if s.adapter == nil {
		return nil, errors.New("api-key: no database adapter")
	}
	rec, err := s.adapter.Create(ctx, ModelName, k.record())
	if err != nil {
		return nil, err
	}
	return fromRecord(rec), nil
}

// dbUpdate applies values (logical fields) to the key with id and returns it, or nil when it is gone.
func (s *Service) dbUpdate(ctx context.Context, id string, values adapter.Record) (*APIKey, error) {
	if s.adapter == nil {
		return nil, errors.New("api-key: no database adapter")
	}
	rec, err := s.adapter.Update(ctx, ModelName, []adapter.Where{{Field: FieldID, Value: id}}, values)
	if errors.Is(err, adapter.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return fromRecord(rec), nil
}

// dbDelete removes the key with id.
func (s *Service) dbDelete(ctx context.Context, id string) error {
	if s.adapter == nil {
		return errors.New("api-key: no database adapter")
	}
	return s.adapter.Delete(ctx, ModelName, []adapter.Where{{Field: FieldID, Value: id}})
}

// ─── Secondary storage ───────────────────────────────────────────────────────

// readStored reads and deserializes one storage key (nil when missing or not a key).
func readStored(ctx context.Context, store kv, key string) (*APIKey, error) {
	v, ok, err := store.get(ctx, key)
	if err != nil || !ok {
		return nil, err
	}
	return deserializeAPIKey(v), nil
}

// readRefList reads the id list of an owner (better-auth tolerates junk: an unreadable list is empty).
func readRefList(ctx context.Context, store kv, refKey string) ([]string, bool, error) {
	v, ok, err := store.get(ctx, refKey)
	if err != nil || !ok {
		return nil, false, err
	}
	var ids []string
	if json.Unmarshal([]byte(v), &ids) != nil {
		return nil, false, nil
	}
	return ids, true, nil
}

// modifyRefList is better-auth's modifyRefList: read-modify-write of an owner's id list (an empty list is
// deleted).
func modifyRefList(ctx context.Context, store kv, refKey string, modify func([]string) []string) error {
	// Step 1: the current list (junk counts as empty)
	ids, _, err := readRefList(ctx, store, refKey)
	if err != nil {
		return err
	}
	// Step 2: write the new list back
	next := modify(ids)
	if len(next) == 0 {
		return store.del(ctx, refKey)
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	return store.set(ctx, refKey, string(raw), 0)
}

// setInStorage is better-auth's setApiKeyInStorage: the key under its hash and its id, plus the owner's id
// list (with fallbackToDatabase the list is only a cache and is dropped instead).
func (s *Service) setInStorage(ctx context.Context, k *APIKey, store kv, opts config.Configuration) error {
	// Step 1: serialize once, store under both keys with the key's remaining lifetime
	serialized, err := serializeAPIKey(k)
	if err != nil {
		return err
	}
	ttl := s.ttlFor(k)
	refKey := storageKeyByReferenceID(k.ReferenceID)
	if err := store.set(ctx, storageKeyByHashedKey(k.Key), serialized, ttl); err != nil {
		return err
	}
	if err := store.set(ctx, storageKeyByID(k.ID), serialized, ttl); err != nil {
		return err
	}
	// Step 2: the owner's list (a cache that is rebuilt from the database with fallbackToDatabase)
	if opts.FallbackToDatabase {
		return store.del(ctx, refKey)
	}
	return modifyRefList(ctx, store, refKey, func(ids []string) []string {
		for _, id := range ids {
			if id == k.ID {
				return ids
			}
		}
		return append(ids, k.ID)
	})
}

// deleteFromStorage is better-auth's deleteApiKeyFromStorage.
func (s *Service) deleteFromStorage(ctx context.Context, k *APIKey, store kv, opts config.Configuration) error {
	refKey := storageKeyByReferenceID(k.ReferenceID)
	if err := store.del(ctx, storageKeyByHashedKey(k.Key)); err != nil {
		return err
	}
	if err := store.del(ctx, storageKeyByID(k.ID)); err != nil {
		return err
	}
	if opts.FallbackToDatabase {
		return store.del(ctx, refKey)
	}
	return modifyRefList(ctx, store, refKey, func(ids []string) []string {
		out := ids[:0:0]
		for _, id := range ids {
			if id != k.ID {
				out = append(out, id)
			}
		}
		return out
	})
}

// ─── Storage-mode dispatch (better-auth's adapter.ts) ────────────────────────

// getByHashedKey is better-auth's getApiKey: the key with this (hashed) value in the configured storage.
func (s *Service) getByHashedKey(ctx context.Context, hashed string, opts config.Configuration) (*APIKey, error) {
	return s.getBy(ctx, FieldKey, hashed, storageKeyByHashedKey(hashed), opts)
}

// getByID is better-auth's getApiKeyById.
func (s *Service) getByID(ctx context.Context, id string, opts config.Configuration) (*APIKey, error) {
	return s.getBy(ctx, FieldID, id, storageKeyByID(id), opts)
}

// getBy reads one key: the database, the secondary storage, or the storage with a database fallback that
// caches what it found.
func (s *Service) getBy(ctx context.Context, field, value, storageKey string, opts config.Configuration) (*APIKey, error) {
	store := s.storageFor(opts)
	switch {
	case opts.Storage == config.StorageSecondary && opts.FallbackToDatabase:
		// Step 1: the cache first
		if store != nil {
			if cached, err := readStored(ctx, store, storageKey); err != nil {
				return nil, err
			} else if cached != nil {
				return cached, nil
			}
		}
		// Step 2: the database, caching the hit
		k, err := s.dbFindOne(ctx, field, value)
		if err != nil || k == nil {
			return k, err
		}
		if store != nil {
			if err := s.setInStorage(ctx, k, store, opts); err != nil {
				return nil, err
			}
		}
		return k, nil
	case opts.Storage == config.StorageSecondary:
		if store == nil {
			return nil, nil
		}
		return readStored(ctx, store, storageKey)
	default:
		return s.dbFindOne(ctx, field, value)
	}
}

// setAPIKey is better-auth's setApiKey: writes the key to the secondary storage (no-op for the database).
func (s *Service) setAPIKey(ctx context.Context, k *APIKey, opts config.Configuration) error {
	if opts.Storage != config.StorageSecondary {
		return nil
	}
	store := s.storageFor(opts)
	if store == nil {
		return errSecondaryStorageRequired
	}
	return s.setInStorage(ctx, k, store, opts)
}

// deleteAPIKeyFromStorage is better-auth's deleteApiKey (adapter.ts): removes the key from the secondary
// storage (no-op for the database).
func (s *Service) deleteAPIKeyFromStorage(ctx context.Context, k *APIKey, opts config.Configuration) error {
	if opts.Storage != config.StorageSecondary {
		return nil
	}
	store := s.storageFor(opts)
	if store == nil {
		return errSecondaryStorageRequired
	}
	return s.deleteFromStorage(ctx, k, store, opts)
}

// removeKey deletes a key from wherever its configuration stores it (the expired / exhausted key paths and
// the delete endpoint).
func (s *Service) removeKey(ctx context.Context, k *APIKey, opts config.Configuration) error {
	switch {
	case opts.Storage == config.StorageSecondary && opts.FallbackToDatabase:
		if err := s.deleteAPIKeyFromStorage(ctx, k, opts); err != nil {
			return err
		}
		return s.dbDelete(ctx, k.ID)
	case opts.Storage == config.StorageSecondary:
		return s.deleteAPIKeyFromStorage(ctx, k, opts)
	default:
		return s.dbDelete(ctx, k.ID)
	}
}

// sortSpec is a list sort (better-auth's sortBy / sortDirection).
type sortSpec struct {
	Field string
	Desc  bool
}

// listByReference is better-auth's listApiKeys (adapter.ts): every key of an owner in one storage.
func (s *Service) listByReference(ctx context.Context, ref string, opts config.Configuration, sortBy *sortSpec) ([]*APIKey, error) {
	store := s.storageFor(opts)
	switch {
	case opts.Storage == config.StorageSecondary && opts.FallbackToDatabase:
		// Step 1: the cached id list, when there is one
		refKey := storageKeyByReferenceID(ref)
		if store != nil {
			ids, _, err := readRefList(ctx, store, refKey)
			if err != nil {
				return nil, err
			}
			if len(ids) > 0 {
				keys, err := s.readMany(ctx, store, ids)
				if err != nil {
					return nil, err
				}
				return sortKeys(keys, sortBy), nil
			}
		}
		// Step 2: the database, then cache every key and the list
		keys, err := s.dbList(ctx, ref, sortBy)
		if err != nil {
			return nil, err
		}
		if store != nil && len(keys) > 0 {
			ids := make([]string, 0, len(keys))
			for _, k := range keys {
				if err := s.setInStorage(ctx, k, store, opts); err != nil {
					return nil, err
				}
				ids = append(ids, k.ID)
			}
			raw, _ := json.Marshal(ids)
			if err := store.set(ctx, refKey, string(raw), 0); err != nil {
				return nil, err
			}
		}
		return keys, nil
	case opts.Storage == config.StorageSecondary:
		if store == nil {
			return nil, nil
		}
		ids, ok, err := readRefList(ctx, store, storageKeyByReferenceID(ref))
		if err != nil || !ok {
			return nil, err
		}
		keys, err := s.readMany(ctx, store, ids)
		if err != nil {
			return nil, err
		}
		return sortKeys(keys, sortBy), nil
	default:
		return s.dbList(ctx, ref, sortBy)
	}
}

// dbList returns an owner's keys from the database, sorted by the database.
func (s *Service) dbList(ctx context.Context, ref string, sortBy *sortSpec) ([]*APIKey, error) {
	if s.adapter == nil {
		return nil, errors.New("api-key: no database adapter")
	}
	q := adapter.Query{Where: []adapter.Where{{Field: FieldReferenceID, Value: ref}}}
	if sortBy != nil {
		q.Sort = []adapter.SortBy{{Field: sortBy.Field, Desc: sortBy.Desc}}
	}
	recs, err := s.adapter.FindMany(ctx, ModelName, q)
	if err != nil {
		return nil, err
	}
	out := make([]*APIKey, 0, len(recs))
	for _, r := range recs {
		out = append(out, fromRecord(r))
	}
	return out, nil
}

// readMany reads keys by id from the storage (missing ones are skipped), at most storageConcurrency at a
// time, keeping the list order.
func (s *Service) readMany(ctx context.Context, store kv, ids []string) ([]*APIKey, error) {
	// Step 1: read in parallel into fixed slots
	results := make([]*APIKey, len(ids))
	errs := make([]error, len(ids))
	sem := make(chan struct{}, storageConcurrency)
	done := make(chan struct{}, len(ids))
	for i, id := range ids {
		sem <- struct{}{}
		go func(i int, id string) {
			defer func() { <-sem; done <- struct{}{} }()
			results[i], errs[i] = readStored(ctx, store, storageKeyByID(id))
		}(i, id)
	}
	for range ids {
		<-done
	}
	// Step 2: keep the keys that exist, in order
	out := make([]*APIKey, 0, len(ids))
	for i, k := range results {
		if errs[i] != nil {
			return nil, errs[i]
		}
		if k != nil {
			out = append(out, k)
		}
	}
	return out, nil
}

// sortKeys is better-auth's applySortingAndPagination sort for keys read from the storage (nulls first in
// ascending order). Unknown fields leave the order unchanged.
func sortKeys(keys []*APIKey, sortBy *sortSpec) []*APIKey {
	if sortBy == nil || sortBy.Field == "" {
		return keys
	}
	sort.SliceStable(keys, func(i, j int) bool {
		c := compareField(keys[i], keys[j], sortBy.Field)
		if sortBy.Desc {
			return c > 0
		}
		return c < 0
	})
	return keys
}

// compareField compares one field of two keys like JavaScript's < / > on the stored values (null first).
func compareField(a, b *APIKey, field string) int {
	av, bv := fieldValue(a, field), fieldValue(b, field)
	switch {
	case av == nil && bv == nil:
		return 0
	case av == nil:
		return -1
	case bv == nil:
		return 1
	}
	switch x := av.(type) {
	case string:
		y, _ := bv.(string)
		return strings.Compare(x, y)
	case float64:
		y, _ := bv.(float64)
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
		return 0
	case bool:
		y, _ := bv.(bool)
		switch {
		case !x && y:
			return -1
		case x && !y:
			return 1
		}
		return 0
	case time.Time:
		y, _ := bv.(time.Time)
		return x.Compare(y)
	}
	return 0
}

// fieldValue returns a field of k as a comparable value (nil for null / unknown fields).
func fieldValue(k *APIKey, field string) any {
	num := func(p *int64) any {
		if p == nil {
			return nil
		}
		return float64(*p)
	}
	tm := func(p *time.Time) any {
		if p == nil {
			return nil
		}
		return *p
	}
	sp := func(p *string) any {
		if p == nil {
			return nil
		}
		return *p
	}
	switch field {
	case FieldID:
		return k.ID
	case FieldConfigID:
		return k.ConfigID
	case FieldName:
		return sp(k.Name)
	case FieldStart:
		return sp(k.Start)
	case FieldReferenceID:
		return k.ReferenceID
	case FieldPrefix:
		return sp(k.Prefix)
	case FieldKey:
		return k.Key
	case FieldRefillInterval:
		return num(k.RefillInterval)
	case FieldRefillAmount:
		return num(k.RefillAmount)
	case FieldLastRefillAt:
		return tm(k.LastRefillAt)
	case FieldEnabled:
		return k.Enabled
	case FieldRateLimitEnabled:
		return k.RateLimitEnabled
	case FieldRateLimitTimeWindow:
		return num(k.RateLimitTimeWindow)
	case FieldRateLimitMax:
		return num(k.RateLimitMax)
	case FieldRequestCount:
		return float64(k.RequestCount)
	case FieldRemaining:
		return num(k.Remaining)
	case FieldLastRequest:
		return tm(k.LastRequest)
	case FieldExpiresAt:
		return tm(k.ExpiresAt)
	case FieldCreatedAt:
		return k.CreatedAt
	case FieldUpdatedAt:
		return k.UpdatedAt
	case FieldPermissions:
		return sp(k.Permissions)
	}
	return nil
}

// storageIdentifier is better-auth's getStorageIdentifier: configurations sharing a backend are listed once.
func storageIdentifier(c config.Configuration) string {
	if c.Storage != config.StorageSecondary {
		return "database"
	}
	if c.CustomStorage != nil {
		id := c.ConfigID
		if id == "" {
			id = config.DefaultConfigID
		}
		return "custom:" + id
	}
	if c.FallbackToDatabase {
		return "secondary-storage-with-fallback"
	}
	return "secondary-storage"
}

// migrateMetadata is better-auth's migrateDoubleStringifiedMetadata: it returns the metadata object and,
// for a legacy double-encoded value stored in the database, writes the decoded object back (a failure is
// only logged).
func (s *Service) migrateMetadata(ctx context.Context, k *APIKey, opts config.Configuration) any {
	parsed := ParseMetadata(k.Metadata)
	if needsMetadataMigration(k.Metadata) && (opts.Storage == config.StorageDatabase || opts.FallbackToDatabase) {
		if _, err := s.dbUpdate(ctx, k.ID, adapter.Record{FieldMetadata: encodeMetadataColumn(parsed)}); err != nil {
			logger.Warn(fmt.Sprintf("Failed to migrate double-stringified metadata for API key %s:", k.ID), "err", err)
		}
	}
	return parsed
}
