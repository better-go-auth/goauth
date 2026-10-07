// Package session implements better-auth style sessions: an opaque token in a signed cookie,
// stored in the database and/or secondary storage, with sliding expiry.
package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
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
	// ID sets the session id (legacy callers pick it before creating); empty generates one.
	ID string
	// goauth extras carried by legacy JWT sessions
	ActiveOrganizationRole *string
	DeviceToken            string
}

// Manager creates, reads, refreshes and revokes sessions.
type Manager struct {
	usersRepo    repo_interfaces.IUserRepo
	sessionsRepo repo_interfaces.ISessionRepo
	secStore     sec_storage.SecondaryStorage
	conf         config.Session
	hooks        plugins.HookRegistry
	now          func() time.Time
}

// NewManager builds a Manager; store and hooks may be nil.
func NewManager(conf config.Session, users repo_interfaces.IUserRepo, sessions repo_interfaces.ISessionRepo, store sec_storage.SecondaryStorage, hooks plugins.HookRegistry) *Manager {
	return &Manager{usersRepo: users, sessionsRepo: sessions, secStore: store, conf: conf, hooks: hooks, now: time.Now}
}

// Config returns the session configuration.
func (m *Manager) Config() config.Session { return m.conf }

func (m *Manager) storeInDB() bool {
	return m.secStore == nil || m.conf.StoreInDatabase()
}

// Create starts a new session for user.
func (m *Manager) Create(ctx context.Context, user *models.User, meta Meta, opt CreateOptions) (*dtos.SessionWithUser, error) {
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
	id := opt.ID
	if id == "" {
		id = models.NewID()
	}
	s := &models.Session{
		Base:                   models.Base{ID: id, CreatedAt: now, UpdatedAt: now},
		Token:                  tok,
		UserID:                 user.ID,
		ExpiresAt:              now.Add(expiresIn),
		IPAddress:              optional(meta.IPAddress),
		UserAgent:              optional(meta.UserAgent),
		ImpersonatedBy:         opt.ImpersonatedBy,
		ActiveOrganizationID:   opt.ActiveOrganizationID,
		ActiveOrganizationRole: opt.ActiveOrganizationRole,
		DeviceToken:            opt.DeviceToken,
	}

	if m.hooks != nil {
		claims := token.CustomClaims{UserID: user.ID, SessionID: s.ID, Role: string(user.Role)}
		if err := m.hooks.TriggerBeforeSessionCreate(ctx, s, &claims); err != nil {
			return nil, err
		}
	}
	if m.storeInDB() {
		if _, err := m.sessionsRepo.CreateSession(ctx, s); err != nil {
			return nil, fmt.Errorf("sessions: create: %w", err)
		}
	}

	sw := &dtos.SessionWithUser{Session: dtos.SessionFromModel(s), User: dtos.UserFromModel(user)}
	if m.secStore != nil {
		if err := m.cache(ctx, sw); err != nil {
			return nil, err
		}
		m.trackActive(ctx, user.ID, tok, s.ExpiresAt)
	}
	return sw, nil
}

// Get returns the live session for tok, or nil when it does not exist or has expired.
func (m *Manager) Get(ctx context.Context, tok string) (*dtos.SessionWithUser, error) {
	if tok == "" {
		return nil, nil
	}
	if m.secStore != nil {
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

	// legacy JWT rows store a 64-hex refresh hash in token; never accept one as a cookie token
	if !idgen.IsToken(tok) {
		return nil, nil
	}
	s, err := m.sessionsRepo.FindSession(ctx, tok)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("sessions: get: %w", err)
	}
	if !s.ExpiresAt.After(m.now()) {
		return nil, m.Delete(ctx, tok)
	}
	user, err := m.usersRepo.FindUserByID(ctx, s.UserID)
	if err != nil || user == nil {
		return nil, nil
	}
	sw := &dtos.SessionWithUser{Session: dtos.SessionFromModel(s), User: dtos.UserFromModel(user)}
	if m.secStore != nil {
		_ = m.cache(ctx, sw)
	}
	return sw, nil
}

// ShouldRefresh applies better-auth's rule: refresh once UpdateAge has passed since expiresAt was last set.
func (m *Manager) ShouldRefresh(sw *dtos.SessionWithUser, dontRemember bool) bool {
	if sw == nil || dontRemember || m.conf.DisableSessionRefresh {
		return false
	}
	dueAt := time.Time(sw.Session.ExpiresAt).Add(-m.conf.ExpiresIn).Add(m.conf.UpdateAge)
	return !dueAt.After(m.now())
}

// Refresh extends the session to now+ExpiresIn.
func (m *Manager) Refresh(ctx context.Context, sw *dtos.SessionWithUser) (*dtos.SessionWithUser, error) {
	now := m.now().UTC()
	expiresAt := now.Add(m.conf.ExpiresIn)
	if m.storeInDB() {
		if _, err := m.sessionsRepo.UpdateSession(ctx, sw.Session.ID, map[string]interface{}{
			"ExpiresAt": expiresAt,
			"UpdatedAt": now,
		}); err != nil {
			if isNotFound(err) {
				return nil, nil
			}
			return nil, fmt.Errorf("sessions: refresh: %w", err)
		}
	}
	out := *sw
	out.Session.ExpiresAt = dtos.Time(expiresAt)
	out.Session.UpdatedAt = dtos.Time(now)
	if m.secStore != nil {
		if err := m.cache(ctx, &out); err != nil {
			return nil, err
		}
		m.trackActive(ctx, sw.Session.UserID, sw.Session.Token, expiresAt)
	}
	return &out, nil
}

// RotateToken gives the session a new token and invalidates the old one (legacy refresh-token rotation).
// It returns nil when the session no longer exists.
func (m *Manager) RotateToken(ctx context.Context, sw *dtos.SessionWithUser) (*dtos.SessionWithUser, error) {
	now := m.now().UTC()
	oldTok, newTok := sw.Session.Token, idgen.GenerateToken()
	out := *sw
	if m.storeInDB() {
		s, err := m.sessionsRepo.UpdateSession(ctx, sw.Session.ID, map[string]interface{}{"Token": newTok, "UpdatedAt": now})
		if err != nil {
			if isNotFound(err) {
				return nil, nil
			}
			return nil, fmt.Errorf("sessions: rotate: %w", err)
		}
		out.Session = dtos.SessionFromModel(s)
	} else {
		if cached, _ := m.fromStore(ctx, oldTok); cached == nil {
			return nil, nil
		}
		out.Session.Token = newTok
		out.Session.UpdatedAt = dtos.Time(now)
	}
	if m.secStore != nil {
		_ = m.secStore.Delete(ctx, oldTok)
		m.untrackActive(ctx, sw.Session.UserID, oldTok)
		if err := m.cache(ctx, &out); err != nil {
			return nil, err
		}
		m.trackActive(ctx, sw.Session.UserID, newTok, time.Time(out.Session.ExpiresAt))
	}
	return &out, nil
}

// IsFresh reports whether the session was created within FreshAge (negative FreshAge disables the check).
func (m *Manager) IsFresh(sw *dtos.SessionWithUser) bool {
	if m.conf.FreshAge < 0 {
		return true
	}
	return m.now().Sub(time.Time(sw.Session.CreatedAt)) < m.conf.FreshAge
}

// Delete revokes a single session.
func (m *Manager) Delete(ctx context.Context, tok string) error {
	var userID string
	if m.secStore != nil {
		if sw, _ := m.fromStore(ctx, tok); sw != nil {
			userID = sw.Session.UserID
		}
		if err := m.secStore.Delete(ctx, tok); err != nil {
			return fmt.Errorf("sessions: delete cached: %w", err)
		}
		if userID != "" {
			m.untrackActive(ctx, userID, tok)
		}
	}
	if m.storeInDB() && !(m.secStore != nil && m.conf.PreserveSessionInDatabase) {
		if err := m.sessionsRepo.DeleteSession(ctx, tok); err != nil {
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
	if m.secStore != nil {
		for _, e := range m.activeList(ctx, userID) {
			_ = m.secStore.Delete(ctx, e.Token)
		}
		_ = m.secStore.Delete(ctx, activeKey(userID))
	}
	if m.storeInDB() && !(m.secStore != nil && m.conf.PreserveSessionInDatabase) {
		if err := m.sessionsRepo.DeleteUserSessions(ctx, userID); err != nil {
			return fmt.Errorf("sessions: delete user sessions: %w", err)
		}
	}
	return nil
}

// Update writes session fields (keyed by Go field name) to the database and the cached copy.
// It returns nil when the session no longer exists.
func (m *Manager) Update(ctx context.Context, sw *dtos.SessionWithUser, data map[string]any) (*dtos.SessionWithUser, error) {
	now := m.now().UTC()
	fields := make(map[string]any, len(data)+1)
	for k, v := range data {
		fields[k] = v
	}
	fields["UpdatedAt"] = now

	out := *sw
	if m.storeInDB() {
		s, err := m.sessionsRepo.UpdateSession(ctx, sw.Session.ID, fields)
		if err != nil {
			if isNotFound(err) {
				return nil, nil
			}
			return nil, fmt.Errorf("sessions: update: %w", err)
		}
		out.Session = dtos.SessionFromModel(s)
	} else {
		if cached, _ := m.fromStore(ctx, sw.Session.Token); cached == nil {
			return nil, nil
		}
		if err := setSessionFields(&out.Session, data); err != nil {
			return nil, err
		}
		out.Session.UpdatedAt = dtos.Time(now)
	}
	if m.secStore != nil {
		if err := m.cache(ctx, &out); err != nil {
			return nil, err
		}
	}
	return &out, nil
}

// setSessionFields applies string/nil values by Go field name to the cached session shape.
func setSessionFields(s *dtos.BetterAuthSession, data map[string]any) error {
	rv := reflect.ValueOf(s).Elem()
	for name, val := range data {
		f := rv.FieldByName(name)
		if !f.IsValid() || !f.CanSet() {
			return fmt.Errorf("sessions: unknown session field %q", name)
		}
		str, isString := val.(string)
		switch {
		case val == nil:
			f.Set(reflect.Zero(f.Type()))
		case isString && f.Kind() == reflect.Pointer && f.Type().Elem().Kind() == reflect.String:
			f.Set(reflect.ValueOf(&str))
		case isString && f.Kind() == reflect.String:
			f.SetString(str)
		default:
			return fmt.Errorf("sessions: cannot set %s to %T", name, val)
		}
	}
	return nil
}

// RefreshUser rewrites the user snapshot of every cached session of user (better-auth's refreshUserSessions).
func (m *Manager) RefreshUser(ctx context.Context, user *models.User) {
	if m.secStore == nil || user == nil {
		return
	}
	for _, e := range m.activeList(ctx, user.ID) {
		if sw, _ := m.fromStore(ctx, e.Token); sw != nil {
			sw.User = dtos.UserFromModel(user)
			_ = m.cache(ctx, sw)
		}
	}
}

// List returns the live sessions of userID.
func (m *Manager) List(ctx context.Context, userID string) ([]dtos.BetterAuthSession, error) {
	now := m.now()
	out := []dtos.BetterAuthSession{}
	if !m.storeInDB() {
		for _, e := range m.activeList(ctx, userID) {
			if sw, _ := m.fromStore(ctx, e.Token); sw != nil && time.Time(sw.Session.ExpiresAt).After(now) {
				out = append(out, sw.Session)
			}
		}
		return out, nil
	}
	rows, err := m.sessionsRepo.ListSessions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("sessions: list: %w", err)
	}
	for i := range rows {
		if idgen.IsToken(rows[i].Token) && rows[i].ExpiresAt.After(now) {
			out = append(out, dtos.SessionFromModel(&rows[i]))
		}
	}
	return out, nil
}

// CleanupExpired deletes expired session rows.
func (m *Manager) CleanupExpired(ctx context.Context) error {
	return m.sessionsRepo.DeleteExpiredSessions(ctx)
}

func (m *Manager) expired(sw *dtos.SessionWithUser) bool {
	return !time.Time(sw.Session.ExpiresAt).After(m.now())
}

// cache stores the session under its token, as better-auth does: key <token> -> {"session","user"}.
func (m *Manager) cache(ctx context.Context, sw *dtos.SessionWithUser) error {
	ttl := time.Time(sw.Session.ExpiresAt).Sub(m.now())
	if ttl <= 0 {
		return nil
	}
	b, err := json.Marshal(sw)
	if err != nil {
		return err
	}
	if err := m.secStore.Set(ctx, sw.Session.Token, string(b), ttl); err != nil {
		return fmt.Errorf("sessions: cache: %w", err)
	}
	return nil
}

func (m *Manager) fromStore(ctx context.Context, tok string) (*dtos.SessionWithUser, error) {
	v, ok, err := m.secStore.Get(ctx, tok)
	if err != nil {
		return nil, fmt.Errorf("sessions: read cache: %w", err)
	}
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

func (m *Manager) activeList(ctx context.Context, userID string) []activeEntry {
	v, ok, err := m.secStore.Get(ctx, activeKey(userID))
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
		_ = m.secStore.Delete(ctx, activeKey(userID))
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
	_ = m.secStore.Set(ctx, activeKey(userID), string(b), ttl)
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
