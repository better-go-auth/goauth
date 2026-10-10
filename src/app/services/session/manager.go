// Package session implements better-auth style sessions: an opaque token in a signed cookie,
// stored in the database and/or secondary storage, with sliding expiry.
package session

import (
	"maps"
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"

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

// Create starts a new session for user.
func (mgr *Manager) Create(ctx context.Context, user *models.User, meta Meta, opt CreateOptions) (*dtos.SessionWithUser, error) {
	// 1. check if user or user.ID is nil / empty, and if so return error
	if user == nil || user.ID == "" {
		return nil, errors.New("sessions: user is required")
	}

	// 2. if dontRemember is set, set lifetime to 24h; otherwise use config or custom ExpiresIn override
	expiresIn := mgr.conf.ExpiresIn
	if opt.DontRemember {
		expiresIn = dontRememberLifetime
	}
	if opt.ExpiresIn > 0 {
		expiresIn = opt.ExpiresIn
	}

	// 3. generate a new 32-char opaque random token and session ID (or use caller-supplied ID)
	now := mgr.now().UTC()
	tok := idgen.GenerateToken()
	id := opt.ID
	if id == "" {
		id = models.NewID()
	}

	// 4. construct session model with timestamps, metadata, and optional plugin context
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

	// 5. trigger BeforeSessionCreate hook if registered (allows plugins like admin ban-check to reject)
	if mgr.hooks != nil {
		claims := token.CustomClaims{UserID: user.ID, SessionID: s.ID, Role: string(user.Role)}
		if err := mgr.hooks.TriggerBeforeSessionCreate(ctx, s, &claims); err != nil {
			return nil, err
		}
	}

	// 6. persist session row to the database if DB storage is enabled
	if mgr.storeInDB() {
		if _, err := mgr.sessionsRepo.CreateSession(ctx, s); err != nil {
			return nil, fmt.Errorf("sessions: create: %w", err)
		}
	}

	// 7. construct session DTO with embedded user snapshot
	swu := &dtos.SessionWithUser{Session: dtos.SessionFromModel(s), User: dtos.UserFromModel(user)}

	// 8. cache session in secondary storage and update user's active-sessions index
	if mgr.secStore != nil {
		if err := mgr.cache(ctx, swu); err != nil {
			return nil, err
		}
		mgr.trackActive(ctx, user.ID, tok, s.ExpiresAt)
	}

	// 9. return the created session
	return swu, nil
}

// Get returns the live session for tok, or nil when it does not exist or has expired.
func (mgr *Manager) Get(ctx context.Context, tok string) (*dtos.SessionWithUser, error) {
	// 1. check if token is empty; if so, return nil immediately
	if tok == "" {
		return nil, nil
	}

	// 2. check secondary storage cache first (if configured)
	if mgr.secStore != nil {
		sSec, err := mgr.fromStore(ctx, tok)
		if err != nil {
			return nil, err
		}
		if sSec != nil {
			// 2a. if cached session is expired, delete it and return nil
			if mgr.expired(sSec) {
				return nil, mgr.Delete(ctx, tok)
			}
			// 2b. *** return valid cached session (zero DB hit)
			return sSec, nil
		}
		// 2c. if cache missed and DB persistence is disabled, session does not exist
		if !mgr.storeInDB() {
			return nil, nil
		}
	}

	// 3. validate token format (reject non-token formats like legacy 64-hex hashes)
	if !idgen.IsToken(tok) {
		return nil, nil
	}

	// 4. lookup session by token in the database
	s, err := mgr.sessionsRepo.FindSession(ctx, tok)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("sessions: get: %w", err)
	}

	// 5. check if the database session has expired; if so, delete it and return nil
	if !s.ExpiresAt.After(mgr.now()) {
		return nil, mgr.Delete(ctx, tok)
	}

	// 6. load the associated user from the user repository
	user, err := mgr.usersRepo.FindUserByID(ctx, s.UserID)
	if err != nil || user == nil {
		return nil, nil
	}

	// 7. construct session with user DTO
	sw := &dtos.SessionWithUser{Session: dtos.SessionFromModel(s), User: dtos.UserFromModel(user)}

	// 8. backfill secondary storage cache with the loaded session
	if mgr.secStore != nil {
		_ = mgr.cache(ctx, sw)
	}

	// 9. return the active session
	return sw, nil
}

// ShouldRefresh applies better-auth's rule: refresh once UpdateAge has passed since expiresAt was last set.
func (mgr *Manager) ShouldRefresh(sw *dtos.SessionWithUser, dontRemember bool) bool {
	// 1. skip refresh if session is nil, dontRemember is true, or session refresh is disabled in config
	if sw == nil || dontRemember || mgr.conf.DisableSessionRefresh {
		return false
	}

	// 2. calculate refresh threshold: (expiresAt - expiresIn + updateAge)
	dueAt := time.Time(sw.Session.ExpiresAt).Add(-mgr.conf.ExpiresIn).Add(mgr.conf.UpdateAge)

	// 3. return true if current time has reached or passed the threshold
	return !dueAt.After(mgr.now())
}

// Refresh extends the session to now+ExpiresIn.
func (mgr *Manager) Refresh(ctx context.Context, swu *dtos.SessionWithUser) (*dtos.SessionWithUser, error) {
	// 1. calculate new expiration timestamp: now + expiresIn
	now := mgr.now().UTC()
	expiresAt := now.Add(mgr.conf.ExpiresIn)

	// 2. update session ExpiresAt and UpdatedAt in the database
	if mgr.storeInDB() {
		if _, err := mgr.sessionsRepo.UpdateSession(ctx, swu.Session.ID, map[string]interface{}{
			"ExpiresAt": expiresAt,
			"UpdatedAt": now,
		}); err != nil {
			if isNotFound(err) {
				return nil, nil
			}
			return nil, fmt.Errorf("sessions: refresh: %w", err)
		}
	}

	// 3. update local in-memory session DTO copy
	out := *swu
	out.Session.ExpiresAt = dtos.Time(expiresAt)
	out.Session.UpdatedAt = dtos.Time(now)

	// 4. update secondary storage cache and update user's active session expiry
	if mgr.secStore != nil {
		if err := mgr.cache(ctx, &out); err != nil {
			return nil, err
		}
		mgr.trackActive(ctx, swu.Session.UserID, swu.Session.Token, expiresAt)
	}

	// 5. return updated session
	return &out, nil
}

// RotateToken gives the session a new token and invalidates the old one (legacy refresh-token rotation).
// It returns nil when the session no longer exists.
func (mgr *Manager) RotateToken(ctx context.Context, swu *dtos.SessionWithUser) (*dtos.SessionWithUser, error) {
	// 1. generate a new token and record current time
	now := mgr.now().UTC()
	oldTok, newTok := swu.Session.Token, idgen.GenerateToken()
	out := *swu

	// 2. update the token in the database or verify it exists in cache
	if mgr.storeInDB() {
		s, err := mgr.sessionsRepo.UpdateSession(ctx, swu.Session.ID, map[string]interface{}{"Token": newTok, "UpdatedAt": now})
		if err != nil {
			if isNotFound(err) {
				return nil, nil
			}
			return nil, fmt.Errorf("sessions: rotate: %w", err)
		}
		out.Session = dtos.SessionFromModel(s)
	} else {
		if cached, _ := mgr.fromStore(ctx, oldTok); cached == nil {
			return nil, nil
		}
		out.Session.Token = newTok
		out.Session.UpdatedAt = dtos.Time(now)
	}

	// 3. remove old token from cache and untrack from active list
	if mgr.secStore != nil {
		_ = mgr.secStore.Delete(ctx, oldTok)
		mgr.untrackActive(ctx, swu.Session.UserID, oldTok)

		// 4. store new token in cache and track in active list
		if err := mgr.cache(ctx, &out); err != nil {
			return nil, err
		}
		mgr.trackActive(ctx, swu.Session.UserID, newTok, time.Time(out.Session.ExpiresAt))
	}

	// 5. return updated session with new token
	return &out, nil
}

// Delete revokes a single session.
func (mgr *Manager) Delete(ctx context.Context, tok string) error {
	var userID string

	// 1. delete from secondary storage cache and untrack from user's active list
	if mgr.secStore != nil {
		if sw, _ := mgr.fromStore(ctx, tok); sw != nil {
			userID = sw.Session.UserID
		}
		if err := mgr.secStore.Delete(ctx, tok); err != nil {
			return fmt.Errorf("sessions: delete cached: %w", err)
		}
		if userID != "" {
			mgr.untrackActive(ctx, userID, tok)
		}
	}

	// 2. delete session row from database (unless PreserveSessionInDatabase is enabled)
	if mgr.storeInDB() && !(mgr.secStore != nil && mgr.conf.PreserveSessionInDatabase) {
		if err := mgr.sessionsRepo.DeleteSession(ctx, tok); err != nil {
			return fmt.Errorf("sessions: delete: %w", err)
		}
	}

	// 3. trigger SessionRevoked lifecycle hook
	if mgr.hooks != nil {
		_ = mgr.hooks.TriggerSessionRevoked(ctx, tok)
	}
	return nil
}

// DeleteUserSessions revokes every session of userID (including legacy JWT sessions in the database).
func (mgr *Manager) DeleteUserSessions(ctx context.Context, userID string) error {
	// 1. delete all cached sessions in secondary storage and delete user active index
	if mgr.secStore != nil {
		for _, e := range mgr.activeList(ctx, userID) {
			_ = mgr.secStore.Delete(ctx, e.Token)
		}
		_ = mgr.secStore.Delete(ctx, activeKey(userID))
	}

	// 2. delete all session rows for user from database (unless preserve is configured)
	if mgr.storeInDB() && !(mgr.secStore != nil && mgr.conf.PreserveSessionInDatabase) {
		if err := mgr.sessionsRepo.DeleteUserSessions(ctx, userID); err != nil {
			return fmt.Errorf("sessions: delete user sessions: %w", err)
		}
	}
	return nil
}

// Update writes session fields (keyed by Go field name) to the database and the cached copy.
// It returns nil when the session no longer exists.
//TODO: instead of map[string]any use a struct
func (mgr *Manager) Update(ctx context.Context, swu *dtos.SessionWithUser, data map[string]any) (*dtos.SessionWithUser, error) {
	// 1. copy update fields and set UpdatedAt to current time
	now := mgr.now().UTC()
	fields := make(map[string]any, len(data)+1)
	maps.Copy(fields, data)
	fields["UpdatedAt"] = now

	out := *swu
	// 2. apply update to database if DB storage is enabled
	if mgr.storeInDB() {
		s, err := mgr.sessionsRepo.UpdateSession(ctx, swu.Session.ID, fields)
		if err != nil {
			if isNotFound(err) {
				return nil, nil
			}
			return nil, fmt.Errorf("sessions: update: %w", err)
		}
		out.Session = dtos.SessionFromModel(s)
	} else {
		// 2b. otherwise verify session exists in cache and update struct via reflection
		if cached, _ := mgr.fromStore(ctx, swu.Session.Token); cached == nil {
			return nil, nil
		}
		if err := setSessionFields(&out.Session, data); err != nil {
			return nil, err
		}
		out.Session.UpdatedAt = dtos.Time(now)
	}

	// 3. sync updated session to secondary storage cache
	if mgr.secStore != nil {
		if err := mgr.cache(ctx, &out); err != nil {
			return nil, err
		}
	}

	// 4. return updated session
	return &out, nil
}

// setSessionFields applies string/nil values by Go field name to the cached session shape.
func setSessionFields(s *dtos.SessionData, data map[string]any) error {
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



// List returns the live sessions of userID.
func (mgr *Manager) List(ctx context.Context, userID string) ([]dtos.SessionData, error) {
	now := mgr.now()
	out := []dtos.SessionData{}

	// 1. if not storing in DB, load active sessions from secondary storage list
	if !mgr.storeInDB() {
		for _, e := range mgr.activeList(ctx, userID) {
			if sw, _ := mgr.fromStore(ctx, e.Token); sw != nil && time.Time(sw.Session.ExpiresAt).After(now) {
				out = append(out, sw.Session)
			}
		}
		return out, nil
	}

	// 2. if storing in DB, query session rows from repository
	rows, err := mgr.sessionsRepo.ListSessions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("sessions: list: %w", err)
	}

	// 3. filter out legacy non-token rows and expired sessions
	for i := range rows {
		if idgen.IsToken(rows[i].Token) && rows[i].ExpiresAt.After(now) {
			out = append(out, dtos.SessionFromModel(&rows[i]))
		}
	}
	return out, nil
}
