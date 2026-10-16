package middleware

import (
	"context"

	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
)

type KeyValRevocationStore struct {
	storage sec_storage.SecondaryStorage
}

func NewKeyValRevocationStore(storage sec_storage.SecondaryStorage) *KeyValRevocationStore {
	return &KeyValRevocationStore{storage: storage}
}

func (r *KeyValRevocationStore) IsRevoked(ctx context.Context, sessionID string) (bool, error) {
	if sessionID == "" || r.storage == nil {
		return false, nil
	}
	_, exists, err := r.storage.Get(ctx, sec_storage.RevokedSessionPrefix+sessionID)
	if err != nil {
		return false, err
	}
	if exists {
		return true, nil
	}
	_, exists, err = r.storage.Get(ctx, sec_storage.LegacyBlacklistPrefix+sessionID)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func (r *KeyValRevocationStore) IsTokenBlacklisted(ctx context.Context, tokenID string) (bool, error) {
	if tokenID == "" || r.storage == nil {
		return false, nil
	}
	_, exists, err := r.storage.Get(ctx, sec_storage.RevokedTokenPrefix+tokenID)
	if err != nil {
		return false, err
	}
	return exists, nil
}
