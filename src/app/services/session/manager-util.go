package session

import (
	"context"
	"net/http"
	"time"

	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/dtos"
)

// Config returns the session configuration.
func (mgr *Manager) Config() config.Session { return mgr.conf }

func (mgr *Manager) storeInDB() bool {
	return mgr.secStore == nil || mgr.conf.StoreInDatabase()
}

// CleanupExpired deletes expired session rows.
func (mgr *Manager) CleanupExpired(ctx context.Context) error {
	return mgr.sessionsRepo.DeleteExpiredSessions(ctx)
}

// checks if the session is expired
func (mgr *Manager) expired(sw *dtos.SessionWithUser) bool {
	return !time.Time(sw.Session.ExpiresAt).After(mgr.now())
}

func asBytes(v any) ([]byte, bool) {
	switch x := v.(type) {
	case string:
		return []byte(x), true
	case []byte:
		return x, true
	}
	return nil, false
}

func isNotFound(err error) bool {
	ae := autherr.AsAuthError(err)
	return ae != nil && ae.StatusCode == http.StatusNotFound
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// IsFresh reports whether the session was created within FreshAge (negative FreshAge disables the check).
func (mgr *Manager) IsFresh(sw *dtos.SessionWithUser) bool {
	// 1. if FreshAge is negative, freshness check is disabled
	if mgr.conf.FreshAge < 0 {
		return true
	}

	// 2. check if time since CreatedAt is within FreshAge window
	return mgr.now().Sub(time.Time(sw.Session.CreatedAt)) < mgr.conf.FreshAge
}
