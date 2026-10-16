package session

import (
	"context"
	"log/slog"

	"github.com/better-go-auth/goauth/src/common/logger"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
)

func (mgr *Manager) fromStore(ctx context.Context, tok string) (*dtos.SessionWithUser, error) {
	// 1. get the session form the secondary storage
	v, ok, err := mgr.secStore.Get(ctx, tok)
	if err != nil {
		return nil, fmt.Errorf("sessions: read cache: %w", err)
	}

	// 2. parse the token into sessionWithUser object an dreturn it
	raw, isText := asBytes(v)
	if !ok || !isText {
		return nil, nil
	}
	var sw dtos.SessionWithUser
	if err := json.Unmarshal(raw, &sw); err != nil || sw.Session.Token != tok {
		return nil, nil
	}
	return &sw, nil
}

type activeEntry struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expiresAt"`
}

func activeKey(userID string) string { return "active-sessions-" + userID }

func (mgr *Manager) activeList(ctx context.Context, userID string) []activeEntry {
	v, ok, err := mgr.secStore.Get(ctx, activeKey(userID))
	raw, isText := asBytes(v)
	if err != nil || !ok || !isText {
		return nil
	}
	var list []activeEntry
	_ = json.Unmarshal(raw, &list)
	return list
}

// trackActive maintains better-auth's "active-sessions-<userId>" index (sorted by expiry, expired pruned).
// "active-sessions-<userId>": [{token:"abc", expiresAt:123}, {token:"xyz", expiresAt:456}]
func (mgr *Manager) trackActive(ctx context.Context, userID, tok string, expiresAt time.Time) {
	// 1. prune expired sessions and avoid duplicates
	nowMs := mgr.now().UnixMilli()
	list := []activeEntry{}
	for _, e := range mgr.activeList(ctx, userID) {
		if e.ExpiresAt > nowMs && e.Token != tok {
			list = append(list, e)
		}
	}
	// 2. append the new session entry
	list = append(list, activeEntry{Token: tok, ExpiresAt: expiresAt.UnixMilli()})
	// 3. sort and save updated index to secondary storage
	mgr.saveActive(ctx, userID, list)
}

func (mgr *Manager) untrackActive(ctx context.Context, userID, tok string) {
	// 1. filter out expired sessions and the specified token to remove
	nowMs := mgr.now().UnixMilli()
	list := []activeEntry{}
	for _, e := range mgr.activeList(ctx, userID) {
		if e.ExpiresAt > nowMs && e.Token != tok {
			list = append(list, e)
		}
	}
	// 2. if no active sessions remain, delete the active index key entirely
	if len(list) == 0 {
		if err := mgr.secStore.Delete(ctx, activeKey(userID)); err != nil {
			logger.ErrorCtx(ctx, "sessions: untrack active-sessions delete failed", err, nil)
			slog.Warn("sessions: untrack active-sessions delete failed", "userID", userID, "err", err)
			incCacheError(ctx)
		}
		return
	}
	// 3. otherwise sort and save the remaining list
	mgr.saveActive(ctx, userID, list)
}

func (mgr *Manager) saveActive(ctx context.Context, userID string, list []activeEntry) {
	// 1. sort active session entries ascending by ExpiresAt
	sort.Slice(list, func(i, j int) bool { return list[i].ExpiresAt < list[j].ExpiresAt })
	// NOTE: read-modify-write without WATCH/Lua can lose entries under concurrent logins; last-write-wins is acceptable for non-Redis stores.
	// 2. compute TTL based on the furthest expiration time in the list
	ttl := time.Until(time.UnixMilli(list[len(list)-1].ExpiresAt))
	if ttl <= 0 {
		return
	}
	// 3. marshal to JSON and save to secondary storage
	b, _ := json.Marshal(list)
	if err := mgr.secStore.Set(ctx, activeKey(userID), string(b), ttl); err != nil {
		logger.ErrorCtx(ctx, "sessions: save active-sessions failed", err, nil)
		slog.Warn("sessions: save active-sessions failed", "userID", userID, "err", err)
		incCacheError(ctx)
	}
}

// cache stores the session under its token with ttl of Session.ExpiresAt, as better-auth does:
// key <token> -> {"session","user"}.
func (mgr *Manager) cache(ctx context.Context, swu *dtos.SessionWithUser) error {
	// 1. calculate TTL remaining until session expiry
	ttl := time.Time(swu.Session.ExpiresAt).Sub(mgr.now())
	if ttl <= 0 {
		return nil
	}
	// 2. serialize session and user snapshot to JSON
	b, err := json.Marshal(swu)
	if err != nil {
		return err
	}
	// 3. write to secondary storage under the session token key
	if err := mgr.secStore.Set(ctx, swu.Session.Token, string(b), ttl); err != nil {
		return fmt.Errorf("sessions: cache: %w", err)
	}
	return nil
}

// RefreshUser rewrites the user snapshot of every cached session of user (better-auth's refreshUserSessions).
func (mgr *Manager) RefreshUser(ctx context.Context, user *models.User) {
	// 1. return early if secondary storage is disabled or user is nil
	if mgr.secStore == nil || user == nil {
		return
	}

	// 2. iterate through user's active session list and rewrite cached user snapshot
	for _, e := range mgr.activeList(ctx, user.ID) {
		if swu, _ := mgr.fromStore(ctx, e.Token); swu != nil {
			swu.User = dtos.UserFromModel(user)
			if err := mgr.cache(ctx, swu); err != nil {
				logger.ErrorCtx(ctx, "sessions: RefreshUser cache failed", err, nil)
				slog.Warn("sessions: RefreshUser cache failed", "userID", user.ID, "err", err)
				incCacheError(ctx)
			}
		}
	}
}
