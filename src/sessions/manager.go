// Package sessions implements better-auth style sessions: an opaque token in a signed cookie,
// stored in the database and/or secondary storage, with sliding expiry.
package sessions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/better-go-auth/goauth/compat"
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/providers/idgen"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
	"github.com/better-go-auth/goauth/src/providers/token"
)

// dontRememberLifetime is better-auth's fixed lifetime for rememberMe=false sessions.
const dontRememberLifetime = 24 * time.Hour

// Meta is request metadata stored on new sessions.
type Meta struct {
	IPAddress string
	UserAgent string
}

// CreateOptions customises a new session.
type CreateOptions struct {
	// DontRemember creates a 1-day session that is never refreshed (rememberMe=false).
	DontRemember         bool
	ExpiresIn            time.Duration
	ImpersonatedBy       *string
	ActiveOrganizationID *string
}

// Manager creates, reads, refreshes and revokes sessions.
type Manager struct {
	users    repo_interfaces.IUserRepo
	sessions repo_interfaces.ISessionRepo
	store    sec_storage.SecondaryStorage
	conf     config.Session
	hooks    plugins.HookRegistry
	now      func() time.Time
}

// NewManager builds a Manager; store and hooks may be nil.
func NewManager(conf config.Session, users repo_interfaces.IUserRepo, sessions repo_interfaces.ISessionRepo, store sec_storage.SecondaryStorage, hooks plugins.HookRegistry) *Manager {
	return &Manager{users: users, sessions: sessions, store: store, conf: conf, hooks: hooks, now: time.Now}
}

// Config returns the session configuration.
func (m *Manager) Config() config.Session { return m.conf }

func (m *Manager) storeInDB() bool {
	return m.store == nil || m.conf.StoreInDatabase()
}

// Create starts a new session for user.
func (m *Manager) Create(ctx context.Context, user *models.User, meta Meta, opt CreateOptions) (*compat.SessionWithUser, error) {
	if user == nil || user.ID == "" {
		return nil, errors.New("sessions: user is required")
	}
	expiresIn := m.conf.ExpiresIn
	if opt.DontRemember {
		expiresIn = dontRememberLifetime
	}
	if opt.ExpiresIn > 0 {
		expiresIn = opt.ExpiresIn
	}
	now := m.now().UTC()
	tok := idgen.GenerateToken()
	s := &models.Session{
		Base:           models.Base{ID: models.NewID(), CreatedAt: &now, UpdatedAt: &now},
		SessionId:      tok,
		Token:          &tok,
		UserID:         user.ID,
		Role:           string(user.Role),
		ExpiresAt:      now.Add(expiresIn),
		IPAddress:      optional(meta.IPAddress),
		UserAgent:      optional(meta.UserAgent),
		ImpersonatedBy: opt.ImpersonatedBy,
		ActiveOrgID:    opt.ActiveOrganizationID,
	}

	if m.hooks != nil {
		claims := token.CustomClaims{UserID: user.ID, SessionID: tok, Role: s.Role}
		if err := m.hooks.TriggerBeforeSessionCreate(ctx, s, &claims); err != nil {
			return nil, err
		}
	}
	if m.storeInDB() {
		if _, err := m.sessions.CreateSession(ctx, s); err != nil {
			return nil, fmt.Errorf("sessions: create: %w", err)
		}
	}

	sw := &compat.SessionWithUser{Session: compat.SessionFromModel(s), User: compat.UserFromModel(user)}
	if m.store != nil {
		if err := m.cache(ctx, sw); err != nil {
			return nil, err
		}
		m.trackActive(ctx, user.ID, tok, s.ExpiresAt)
	}
	return sw, nil
}

// Get returns the live session for tok, or nil when it does not exist or has expired.
func (m *Manager) Get(ctx context.Context, tok string) (*compat.SessionWithUser, error) {
	if tok == "" {
		return nil, nil
	}
	if m.store != nil {
		sw, err := m.fromStore(ctx, tok)
		if err != nil {
			return nil, err
		}
		if sw != nil {
			if m.expired(sw) {
				return nil, m.Delete(ctx, tok)
			}
			return sw, nil
		}
		if !m.storeInDB() {
			return nil, nil
		}
	}

	s, err := m.sessions.GetSessionBySessionID(ctx, tok)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("sessions: get: %w", err)
	}
	// legacy JWT sessions share the table but have no token
	if s.Token == nil || *s.Token != tok {
		return nil, nil
	}
	if !s.ExpiresAt.After(m.now()) {
		return nil, m.Delete(ctx, tok)
	}
	user, err := m.users.GetUserByID(ctx, s.UserID)
	if err != nil || user == nil {
		return nil, nil
	}
	sw := &compat.SessionWithUser{Session: compat.SessionFromModel(s), User: compat.UserFromModel(user)}
	if m.store != nil {
		_ = m.cache(ctx, sw)
	}
	return sw, nil
}

// ShouldRefresh applies better-auth's rule: refresh once UpdateAge has passed since expiresAt was last set.
func (m *Manager) ShouldRefresh(sw *compat.SessionWithUser, dontRemember bool) bool {
	if sw == nil || dontRemember || m.conf.DisableSessionRefresh {
		return false
	}
	dueAt := time.Time(sw.Session.ExpiresAt).Add(-m.conf.ExpiresIn).Add(m.conf.UpdateAge)
	return !dueAt.After(m.now())
}

// Refresh extends the session to now+ExpiresIn.
func (m *Manager) Refresh(ctx context.Context, sw *compat.SessionWithUser) (*compat.SessionWithUser, error) {
	now := m.now().UTC()
	expiresAt := now.Add(m.conf.ExpiresIn)
	if m.storeInDB() {
		if _, err := m.sessions.UpdateSession(ctx, sw.Session.Token, map[string]interface{}{
			"expires_at": expiresAt,
			"updated_at": now,
		}); err != nil {
			if isNotFound(err) {
				return nil, nil
			}
			return nil, fmt.Errorf("sessions: refresh: %w", err)
		}
	}
	out := *sw
	out.Session.ExpiresAt = compat.Time(expiresAt)
	out.Session.UpdatedAt = compat.Time(now)
	if m.store != nil {
		if err := m.cache(ctx, &out); err != nil {
			return nil, err
		}
		m.trackActive(ctx, sw.Session.UserID, sw.Session.Token, expiresAt)
	}
	return &out, nil
}

// IsFresh reports whether the session was created within FreshAge (negative FreshAge disables the check).
func (m *Manager) IsFresh(sw *compat.SessionWithUser) bool {
	if m.conf.FreshAge < 0 {
		return true
	}
	return m.now().Sub(time.Time(sw.Session.CreatedAt)) < m.conf.FreshAge
}

// Delete revokes a single session.
func (m *Manager) Delete(ctx context.Context, tok string) error {
	var userID string
	if m.store != nil {
		if sw, _ := m.fromStore(ctx, tok); sw != nil {
			userID = sw.Session.UserID
		}
		if err := m.store.Delete(ctx, tok); err != nil {
			return fmt.Errorf("sessions: delete cached: %w", err)
		}
		if userID != "" {
			m.untrackActive(ctx, userID, tok)
		}
	}
	if m.storeInDB() && !(m.store != nil && m.conf.PreserveSessionInDatabase) {
		if err := m.sessions.DeleteSession(ctx, tok); err != nil {
			return fmt.Errorf("sessions: delete: %w", err)
		}
	}
	if m.hooks != nil {
		_ = m.hooks.TriggerSessionRevoked(ctx, tok)
	}
	return nil
}

// DeleteUserSessions revokes every session of userID (including legacy JWT sessions in the database).
func (m *Manager) DeleteUserSessions(ctx context.Context, userID string) error {
	if m.store != nil {
		for _, e := range m.activeList(ctx, userID) {
			_ = m.store.Delete(ctx, e.Token)
		}
		_ = m.store.Delete(ctx, activeKey(userID))
	}
	if m.storeInDB() && !(m.store != nil && m.conf.PreserveSessionInDatabase) {
		if err := m.sessions.DeleteSessionsByUserID(ctx, userID); err != nil {
			return fmt.Errorf("sessions: delete user sessions: %w", err)
		}
	}
	return nil
}

// List returns the live sessions of userID.
func (m *Manager) List(ctx context.Context, userID string) ([]compat.BetterAuthSession, error) {
	now := m.now()
	out := []compat.BetterAuthSession{}
	if !m.storeInDB() {
		for _, e := range m.activeList(ctx, userID) {
			if sw, _ := m.fromStore(ctx, e.Token); sw != nil && time.Time(sw.Session.ExpiresAt).After(now) {
				out = append(out, sw.Session)
			}
		}
		return out, nil
	}
	rows, err := m.sessions.ListSessionsByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("sessions: list: %w", err)
	}
	for i := range rows {
		if rows[i].Token != nil && rows[i].ExpiresAt.After(now) {
			out = append(out, compat.SessionFromModel(&rows[i]))
		}
	}
	return out, nil
}

// CleanupExpired deletes expired session rows when the repository supports it.
func (m *Manager) CleanupExpired(ctx context.Context) error {
	if r, ok := m.sessions.(interface{ DeleteExpired(context.Context) error }); ok {
		return r.DeleteExpired(ctx)
	}
	return nil
}

func (m *Manager) expired(sw *compat.SessionWithUser) bool {
	return !time.Time(sw.Session.ExpiresAt).After(m.now())
}

// cache stores the session under its token, as better-auth does: key <token> -> {"session","user"}.
func (m *Manager) cache(ctx context.Context, sw *compat.SessionWithUser) error {
	ttl := time.Time(sw.Session.ExpiresAt).Sub(m.now())
	if ttl <= 0 {
		return nil
	}
	b, err := json.Marshal(sw)
	if err != nil {
		return err
	}
	if err := m.store.Set(ctx, sw.Session.Token, string(b), ttl); err != nil {
		return fmt.Errorf("sessions: cache: %w", err)
	}
	return nil
}

func (m *Manager) fromStore(ctx context.Context, tok string) (*compat.SessionWithUser, error) {
	v, ok, err := m.store.Get(ctx, tok)
	if err != nil {
		return nil, fmt.Errorf("sessions: read cache: %w", err)
	}
	raw, isText := asBytes(v)
	if !ok || !isText {
		return nil, nil
	}
	var sw compat.SessionWithUser
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

func (m *Manager) activeList(ctx context.Context, userID string) []activeEntry {
	v, ok, err := m.store.Get(ctx, activeKey(userID))
	raw, isText := asBytes(v)
	if err != nil || !ok || !isText {
		return nil
	}
	var list []activeEntry
	_ = json.Unmarshal(raw, &list)
	return list
}

// trackActive maintains better-auth's "active-sessions-<userId>" index (sorted by expiry, expired pruned).
func (m *Manager) trackActive(ctx context.Context, userID, tok string, expiresAt time.Time) {
	nowMs := m.now().UnixMilli()
	list := []activeEntry{}
	for _, e := range m.activeList(ctx, userID) {
		if e.ExpiresAt > nowMs && e.Token != tok {
			list = append(list, e)
		}
	}
	list = append(list, activeEntry{Token: tok, ExpiresAt: expiresAt.UnixMilli()})
	m.saveActive(ctx, userID, list)
}

func (m *Manager) untrackActive(ctx context.Context, userID, tok string) {
	nowMs := m.now().UnixMilli()
	list := []activeEntry{}
	for _, e := range m.activeList(ctx, userID) {
		if e.ExpiresAt > nowMs && e.Token != tok {
			list = append(list, e)
		}
	}
	if len(list) == 0 {
		_ = m.store.Delete(ctx, activeKey(userID))
		return
	}
	m.saveActive(ctx, userID, list)
}

func (m *Manager) saveActive(ctx context.Context, userID string, list []activeEntry) {
	sort.Slice(list, func(i, j int) bool { return list[i].ExpiresAt < list[j].ExpiresAt })
	ttl := time.Until(time.UnixMilli(list[len(list)-1].ExpiresAt))
	if ttl <= 0 {
		return
	}
	b, _ := json.Marshal(list)
	_ = m.store.Set(ctx, activeKey(userID), string(b), ttl)
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
