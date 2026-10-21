package providers

import (
	"context"
	"reflect"
	"time"

	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/common/middleware"
	"github.com/better-go-auth/goauth/src/models"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
	"gorm.io/gorm"
)

// var _ middleware.RevocationStore = (*RevocationStore)(nil)

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

// SessionRevocationChecker defines methods needed by RevocationStore to verify session validity.
type SessionRevocationChecker interface {
	FindSessionByID(ctx context.Context, id string) (*models.Session, error)
}

// RevocationConfig configures revocation checking behavior.
type RevocationConfig struct {
	// CheckRevocation verifies session validity in repository/DB on every request.
	CheckRevocation bool
}

// RevocationStore checks if a session or token has been revoked or invalidated.
type RevocationStore struct {
	db          *gorm.DB
	sessionRepo SessionRevocationChecker
	secStore    sec_storage.SecondaryStorage
	cfg         RevocationConfig
}

//TODO: remove this because it depends on db
// NewRevocationStore creates a RevocationStore backed by database and optional key-value storage.
func NewRevocationStore(db *gorm.DB, secStore sec_storage.SecondaryStorage, cfg RevocationConfig) middleware.RevocationStore {
	if isNil(secStore) {
		secStore = nil
	}
	if isNil(db) {
		db = nil
	}
	rs := &RevocationStore{
		db:       db,
		secStore: secStore,
		cfg:      cfg,
	}
	if db != nil {
		rs.sessionRepo = gormSessionChecker{db: db}
	}
	return rs
}

// TODO: remove all gorm dependent funcitons: abstract the connection with repo
type gormSessionChecker struct {
	db *gorm.DB
}

func (g gormSessionChecker) FindSessionByID(ctx context.Context, id string) (*models.Session, error) {
	var sess models.Session
	err := gormutil.GetDB(ctx, g.db).
		Select(gormutil.ColNames(g.db, &models.Session{}, "ID", "ExpiresAt")).
		Where(&models.Session{Base: models.Base{ID: id}}, "ID").
		Take(&sess).Error
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

// NewRevocationStoreWithRepo creates a RevocationStore backed by a SessionRevocationChecker repository.
func NewRevocationStoreWithRepo(repo SessionRevocationChecker, store sec_storage.SecondaryStorage, cfg RevocationConfig) *RevocationStore {
	if isNil(store) {
		store = nil
	}
	if isNil(repo) {
		repo = nil
	}
	return &RevocationStore{
		sessionRepo: repo,
		secStore:    store,
		cfg:         cfg,
	}
}

// IsRevoked checks whether a given sessionID has been revoked, blacklisted, expired, or deleted.
func (r *RevocationStore) IsRevoked(ctx context.Context, sessionID string) (bool, error) {
	if sessionID == "" {
		return false, nil
	}

	// 1. Check secondary storage (e.g. Redis) if available
	if r.secStore != nil {
		if exists, err := r.secStore.Exists(ctx, sec_storage.RevokedSessionPrefix+sessionID); err == nil && exists {
			return true, nil
		}
	}

	if r.cfg.CheckRevocation {
		// 2. Check via session repository interface if configured
		if r.sessionRepo != nil {
			sess, err := r.sessionRepo.FindSessionByID(ctx, sessionID)
			if err != nil {
				// Not found in DB => revoked/deleted
				return true, nil
			}
			if sess == nil {
				return true, nil
			}
			if !sess.ExpiresAt.IsZero() && time.Now().After(sess.ExpiresAt) {
				return true, nil
			}
			return false, nil
		}
	}

	return false, nil
}

// IsTokenBlacklisted is kept for interface compat; token blacklist is not used.
func (r *RevocationStore) IsTokenBlacklisted(ctx context.Context, tokenID string) (bool, error) {
	return false, nil
}
