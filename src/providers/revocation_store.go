package providers

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/birukbelay/gocmn/src/provider/db"
	"github.com/birukbelay/gocmn/src/server/middleware"
	"gorm.io/gorm"
)

var _ middleware.RevocationStore = (*RevocationStore)(nil)

func isNil(i any) bool {
	if i == nil {
		return true
	}
	v := reflect.ValueOf(i)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.UnsafePointer, reflect.Interface, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

// RevocationStore checks if a session or token has been revoked or invalidated.
type RevocationStore struct {
	db    *gorm.DB
	store db.KeyValServ
}

// NewRevocationStore creates a RevocationStore backed by database and optional key-value storage.
func NewRevocationStore(db *gorm.DB, store db.KeyValServ) *RevocationStore {
	if isNil(store) {
		store = nil
	}
	if isNil(db) {
		db = nil
	}
	return &RevocationStore{
		db:    db,
		store: store,
	}
}

// IsRevoked checks whether a given sessionID has been revoked, blacklisted, expired, or deleted.
func (r *RevocationStore) IsRevoked(ctx context.Context, sessionID string) (bool, error) {
	if sessionID == "" {
		return false, nil
	}

	// 1. Check secondary storage (e.g. Redis) if available
	if r.store != nil {
		if exists, err := r.store.Exists(ctx, "blacklist:"+sessionID); err == nil && exists {
			return true, nil
		}
		if exists, err := r.store.Exists(ctx, "revoked:session:"+sessionID); err == nil && exists {
			return true, nil
		}
	}

	// 2. Check the database
	if r.db != nil {
		var sess models.Session
		err := gormutil.GetDB(ctx, r.db).
			Select("id", "session_id", "blacklisted", "revoked_at", "expires_at").
			Where("session_id = ?", sessionID).
			Take(&sess).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				// Session not found in DB => revoked/deleted
				return true, nil
			}
			return false, err
		}
		if sess.Blacklisted != nil && *sess.Blacklisted {
			return true, nil
		}
		if sess.RevokedAt != nil {
			return true, nil
		}
		if !sess.ExpiresAt.IsZero() && time.Now().After(sess.ExpiresAt) {
			return true, nil
		}
	}

	return false, nil
}

// IsTokenBlacklisted checks whether a token has been explicitly blacklisted.
func (r *RevocationStore) IsTokenBlacklisted(ctx context.Context, tokenID string) (bool, error) {
	if tokenID == "" {
		return false, nil
	}
	if r.store != nil {
		if exists, err := r.store.Exists(ctx, "blacklist:token:"+tokenID); err == nil && exists {
			return true, nil
		}
	}
	return false, nil
}
