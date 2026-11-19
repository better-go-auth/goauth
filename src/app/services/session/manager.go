// Package session implements better-auth style sessions: an opaque token in a signed cookie,
// stored in the database and/or secondary storage, with sliding expiry.
package session

import (
	"context"

	"errors"
	"fmt"
	"github.com/better-go-auth/goauth/src/common/logger"
	"maps"
	"sync"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/adapterrepo"
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/app/services/interfaces"

	"github.com/better-go-auth/goauth/src/common/dbhooks"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/providers/idgen"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
	"github.com/better-go-auth/goauth/src/providers/token"
	"github.com/better-go-auth/goauth/src/schema"
)

// dontRememberLifetime is better-auth's fixed lifetime for rememberMe=false sessions.
const dontRememberLifetime = 24 * time.Hour

// Meta is request metadata stored on new sessions.
type Meta = interfaces.SessionMeta

// CreateOptions customises a new session.
type CreateOptions = interfaces.SessionCreateOptions

// Manager creates, reads, refreshes and revokes sessions.
type Manager struct {
	usersRepo    repo_interfaces.IUserRepo
	sessionsRepo repo_interfaces.ISessionRepo
	secStore     sec_storage.SecondaryStorage
	conf         config.Session
	hooks        plugins.HookRegistry
	now          func() time.Time
	generateID   func() string
	activeMu     sync.Mutex
	// dbHooks are better-auth's database hooks; the repositories run them for database writes, the manager
	// for sessions that only live in secondary storage
	dbHooks *dbhooks.Set
	// reg is the schema registry: session additionalFields defaults on create
	reg *schema.Registry
}

var _ interfaces.ISessionManager = (*Manager)(nil)

// ManagerOption configures a Manager.
type ManagerOption func(*Manager)

// WithClock overrides the clock used for expiry/refresh checks (for tests).
func WithClock(fn func() time.Time) ManagerOption { return func(m *Manager) { m.now = fn } }

// WithGenerateID overrides the ID generator used for new sessions (default idgen.GenerateID).
func WithGenerateID(fn func() string) ManagerOption { return func(m *Manager) { m.generateID = fn } }

// WithDatabaseHooks runs better-auth's session database hooks for sessions stored only in secondary storage
// (database writes run them in the repositories, see hookedrepo).
func WithDatabaseHooks(set *dbhooks.Set) ManagerOption { return func(m *Manager) { m.dbHooks = set } }

// WithRegistry gives new sessions the defaults of the session schema's additional fields (better-auth's
// getSessionDefaultFields).
func WithRegistry(reg *schema.Registry) ManagerOption { return func(m *Manager) { m.reg = reg } }

// WithManagerOptions applies options to an existing Manager (for tests wiring after NewManager).
func (mgr *Manager) WithOptions(opts ...ManagerOption) {
	for _, o := range opts {
		o(mgr)
	}
}

// NewManager builds a Manager; store and hooks may be nil.
func NewManager(conf config.Session, users repo_interfaces.IUserRepo, sessions repo_interfaces.ISessionRepo, store sec_storage.SecondaryStorage, hooks plugins.HookRegistry, opts ...ManagerOption) *Manager {
	if !conf.StoreSessionInDatabaseSet && !conf.StoreSessionInDatabase {
		conf.StoreSessionInDatabase = true
	}
	mgr := &Manager{usersRepo: users, sessionsRepo: sessions, secStore: store, conf: conf, hooks: hooks, now: time.Now, generateID: idgen.GenerateID}
	for _, o := range opts {
		o(mgr)
	}
	if hooks != nil {
		hooks.OnUserBanned(func(ctx context.Context, userID string, reason *string) error {
			return mgr.DeleteUserSessions(ctx, userID)
		})
	}
	return mgr
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
		if mgr.generateID != nil {
			id = mgr.generateID()
		} else {
			id = idgen.GenerateID()
		}
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
		ActiveOrganizationType: opt.ActiveOrganizationType,
		DeviceToken:            opt.DeviceToken,
	}
	// 4b. session additionalFields: the caller's values, then the schema defaults (getSessionDefaultFields)
	mgr.applySessionExtras(s, opt.Extra)

	// 5. trigger BeforeSessionCreate hook if registered (allows plugins like admin ban-check to reject)
	if mgr.hooks != nil {
		claims := token.CustomClaims{UserID: user.ID, SessionID: s.ID, Role: string(user.Role)}
		if err := mgr.hooks.TriggerBeforeSessionCreate(ctx, s, &claims); err != nil {
			return nil, err
		}
	}

	// 6. persist session row to the database if DB storage is enabled (the repositories run the session
	// database hooks); sessions only kept in secondary storage run them here, like better-auth's
	// createWithHooks with a custom create function
	if mgr.storeInDB() {
		if _, err := mgr.sessionsRepo.CreateSession(ctx, s); err != nil {
			return nil, fmt.Errorf("sessions: create: %w", err)
		}
	} else if err := dbhooks.RunCreateBefore(ctx, mgr.dbHooks, dbhooks.Session, s); err != nil {
		return nil, fmt.Errorf("sessions: create: %w", err)
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

	// 9. remember the session on the request (after-request hooks such as anonymous account linking)
	recordNewSession(ctx, swu)

	// 9b. create.after hooks of sessions that only live in secondary storage
	if !mgr.storeInDB() {
		if err := dbhooks.RunCreateAfter(ctx, mgr.dbHooks, dbhooks.Session, s); err != nil {
			return nil, err
		}
	}

	// 10. return the created session
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
		if err := mgr.cache(ctx, sw); err != nil {
			logger.Warn("sessions: cache backfill failed", "err", err)
			incCacheError(ctx)
		}
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
		if _, err := mgr.sessionsRepo.UpdateSession(ctx, swu.Session.ID, map[string]any{
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

// RotateToken gives the session a new token and invalidates the old one: is an option for session security.
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
	var revokedSession *models.Session

	// 1. delete from secondary storage cache and untrack from user's active list
	if mgr.secStore != nil {
		if sw, _ := mgr.fromStore(ctx, tok); sw != nil {
			userID = sw.Session.UserID
			revokedSession = &models.Session{
				Base:      models.Base{ID: sw.Session.ID, CreatedAt: time.Time(sw.Session.CreatedAt), UpdatedAt: time.Time(sw.Session.UpdatedAt)},
				Token:     tok,
				UserID:    sw.Session.UserID,
				ExpiresAt: time.Time(sw.Session.ExpiresAt),
			}
		}
		if err := mgr.secStore.Delete(ctx, tok); err != nil {
			return fmt.Errorf("sessions: delete cached: %w", err)
		}
		if userID != "" {
			mgr.untrackActive(ctx, userID, tok)
		}
	}

	// 2. delete session row from database (unless PreserveSessionInDatabase is enabled)
	if mgr.storeInDB() {
		if revokedSession == nil && mgr.sessionsRepo != nil {
			if s, _ := mgr.sessionsRepo.FindSession(ctx, tok); s != nil {
				revokedSession = s
			}
		}
		if !(mgr.secStore != nil && mgr.conf.PreserveSessionInDatabase) {
			if err := mgr.sessionsRepo.DeleteSession(ctx, tok); err != nil {
				return fmt.Errorf("sessions: delete: %w", err)
			}
		}
	}

	// 3. trigger SessionRevoked lifecycle hook
	if mgr.hooks != nil {
		if revokedSession == nil {
			revokedSession = &models.Session{Token: tok}
		}
		_ = mgr.hooks.TriggerSessionRevoked(ctx, revokedSession)
	}
	return nil
}

// DeleteUserSessions revokes every session of userID (including legacy JWT sessions in the database).
func (mgr *Manager) DeleteUserSessions(ctx context.Context, userID string) error {
	// 1. delete all cached sessions in secondary storage and delete user active index
	if mgr.secStore != nil {
		for _, e := range mgr.activeList(ctx, userID) {
			if err := mgr.secStore.Delete(ctx, e.Token); err != nil {
				logger.Warn("sessions: delete cached token failed", "err", err)
				incCacheError(ctx)
			}
		}
		if err := mgr.secStore.Delete(ctx, activeKey(userID)); err != nil {
			logger.Warn("sessions: delete active-sessions index failed", "userID", userID, "err", err)
		}
	}

	// 2. delete all session rows for user from database (unless preserve is configured)
	if mgr.storeInDB() && !(mgr.secStore != nil && mgr.conf.PreserveSessionInDatabase) {
		if err := mgr.sessionsRepo.DeleteUserSessions(ctx, userID); err != nil {
			return fmt.Errorf("sessions: delete user sessions: %w", err)
		}
	}
	return nil
}

// Deprecated: Use UpdatePatch instead to avoid map allocations.
// Update writes session fields (keyed by Go field name) to the database and the cached copy.
// It returns nil when the session no longer exists.
func (mgr *Manager) Update(ctx context.Context, swu *dtos.SessionWithUser, data map[string]any) (*dtos.SessionWithUser, error) {
	now := mgr.now().UTC()
	fields := make(map[string]any, len(data)+1)
	maps.Copy(fields, repoSessionKeys(data))
	fields["UpdatedAt"] = now

	out := *swu
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
		if cached, _ := mgr.fromStore(ctx, swu.Session.Token); cached == nil {
			return nil, nil
		}
		// better-auth's updateWithHooks with a custom update function: the hooks see the changes by field name
		changes := sessionChanges(data)
		if err := dbhooks.RunUpdateBefore(ctx, mgr.dbHooks, dbhooks.Session, changes); err != nil {
			if dbhooks.IsCancel(err) {
				return swu, nil
			}
			return nil, err
		}
		if err := setSessionChanges(&out.Session, changes); err != nil {
			return nil, err
		}
		out.Session.UpdatedAt = dtos.Time(now)
		defer func() {
			_ = dbhooks.RunUpdateAfter(ctx, mgr.dbHooks, dbhooks.Session, sessionModel(&out))
		}()
	}

	if mgr.secStore != nil {
		if err := mgr.cache(ctx, &out); err != nil {
			return nil, err
		}
	}
	return &out, nil
}

// setSessionFields applies string/nil values by Go field name without reflection overhead.
func setSessionFields(s *dtos.SessionData, data map[string]any) error {
	for name, val := range data {
		var strPtr *string
		switch v := val.(type) {
		case nil:
			strPtr = nil
		case string:
			strPtr = &v
		case *string:
			strPtr = v
		default:
			return fmt.Errorf("sessions: cannot set %s to %T", name, val)
		}

		switch name {
		case "ActiveOrganizationID":
			s.ActiveOrganizationID = strPtr
		case "ActiveOrganizationRole":
			s.ActiveOrganizationRole = strPtr
		case "ActiveOrganizationType", "ActiveOrgType":
			s.ActiveOrganizationType = strPtr
		case "ActiveTeamID":
			s.ActiveTeamID = strPtr
		case "DeviceToken":
			s.DeviceToken = strPtr
		case "DeviceID":
			s.DeviceID = strPtr
		case "DeviceName":
			s.DeviceName = strPtr
		case "DeviceType":
			s.DeviceType = strPtr
		case "ImpersonatedBy":
			s.ImpersonatedBy = strPtr
		default:
			return fmt.Errorf("sessions: unknown session field %q", name)
		}
	}
	return nil
}

func applyPatch(s *dtos.SessionData, patch config.SessionPatch) {
	if patch.ActiveOrganizationID != nil {
		s.ActiveOrganizationID = patch.ActiveOrganizationID
	}
	if patch.ActiveOrganizationRole != nil {
		s.ActiveOrganizationRole = patch.ActiveOrganizationRole
	}
	if patch.ActiveOrganizationType != nil {
		s.ActiveOrganizationType = patch.ActiveOrganizationType
	}
	if patch.ActiveTeamID != nil {
		s.ActiveTeamID = patch.ActiveTeamID
	}
	if patch.DeviceToken != nil {
		s.DeviceToken = patch.DeviceToken
	}
	if patch.DeviceID != nil {
		s.DeviceID = patch.DeviceID
	}
	if patch.DeviceName != nil {
		s.DeviceName = patch.DeviceName
	}
	if patch.DeviceType != nil {
		s.DeviceType = patch.DeviceType
	}
}

// UpdatePatch is the typed version of Update — applies SessionPatch with zero reflection.
func (mgr *Manager) UpdatePatch(ctx context.Context, swu *dtos.SessionWithUser, patch config.SessionPatch) (*dtos.SessionWithUser, error) {
	if swu == nil {
		return nil, errors.New("sessions: session is required")
	}
	copied := *swu
	sess := copied.Session
	applyPatch(&sess, patch)
	copied.Session = sess

	if mgr.storeInDB() {
		data := patch.ToMap()
		if len(data) > 0 {
			s, err := mgr.sessionsRepo.UpdateSession(ctx, sess.ID, data)
			if err != nil {
				return nil, fmt.Errorf("sessions: update: %w", err)
			}
			if s != nil {
				copied.Session = dtos.SessionFromModel(s)
			}
		}
	}
	if mgr.secStore != nil {
		_ = mgr.cache(ctx, &copied)
	}
	return &copied, nil
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

// applySessionExtras sets the caller's additional session fields, then the defaults of the session
// schema's input fields that are still unset (better-auth's getSessionDefaultFields).
func (mgr *Manager) applySessionExtras(s *models.Session, extra map[string]any) {
	// Step 1: values given by the caller (registry field names)
	for k, v := range extra {
		if v != nil {
			s.SetExtra(k, v)
		}
	}
	if mgr.reg == nil {
		return
	}
	m, ok := mgr.reg.Model(schema.ModelSession)
	if !ok {
		return
	}
	// Step 2: defaults of runtime fields (static Go fields have their own zero values / column defaults)
	for _, f := range m.InputFields() {
		if !f.HasDefault() {
			continue
		}
		if _, static := adapterrepo.GoFieldName(schema.ModelSession, f.Name); static {
			continue
		}
		if _, set := s.Extra[f.Name]; set {
			continue
		}
		if v, err := schema.Normalize(f.Type, f.DefaultValue()); err == nil {
			s.SetExtra(f.Name, v)
		}
	}
}

// sessionChanges converts a session update keyed by Go field names (or field names) to field names.
func sessionChanges(data map[string]any) map[string]any {
	out := make(map[string]any, len(data))
	for k, v := range data {
		if name, ok := adapterrepo.FieldName(schema.ModelSession, k); ok {
			k = name
		}
		out[k] = v
	}
	return out
}

// repoSessionKeys converts a session update keyed by field names to the keys every repository understands
// (Go field names for the struct's fields, field names for runtime fields).
func repoSessionKeys(data map[string]any) map[string]any {
	out := make(map[string]any, len(data))
	for k, v := range data {
		if goName, ok := adapterrepo.GoFieldName(schema.ModelSession, k); ok {
			k = goName
		}
		out[k] = v
	}
	return out
}

// setSessionChanges applies field-name changes to a cached session: struct fields by Go name, the others
// into Extra (nil removes them).
func setSessionChanges(s *dtos.SessionData, changes map[string]any) error {
	static := map[string]any{}
	for k, v := range changes {
		if goName, ok := adapterrepo.GoFieldName(schema.ModelSession, k); ok {
			static[goName] = v
			continue
		}
		if s.Extra == nil {
			s.Extra = map[string]any{}
		}
		if v == nil {
			delete(s.Extra, k)
		} else {
			s.Extra[k] = v
		}
	}
	return setSessionFields(s, static)
}

// sessionModel converts a cached session back to the model database hooks receive.
func sessionModel(sw *dtos.SessionWithUser) *models.Session {
	d := sw.Session
	s := &models.Session{
		Base:                   models.Base{ID: d.ID, CreatedAt: time.Time(d.CreatedAt), UpdatedAt: time.Time(d.UpdatedAt)},
		Token:                  d.Token,
		UserID:                 d.UserID,
		ExpiresAt:              time.Time(d.ExpiresAt),
		IPAddress:              d.IPAddress,
		UserAgent:              d.UserAgent,
		ImpersonatedBy:         d.ImpersonatedBy,
		ActiveOrganizationID:   d.ActiveOrganizationID,
		ActiveOrganizationType: d.ActiveOrganizationType,
		ActiveOrganizationRole: d.ActiveOrganizationRole,
		ActiveTeamID:           d.ActiveTeamID,
		DeviceID:               d.DeviceID,
		DeviceName:             d.DeviceName,
		DeviceType:             d.DeviceType,
	}
	if d.DeviceToken != nil {
		s.DeviceToken = *d.DeviceToken
	}
	for k, v := range d.Extra {
		s.SetExtra(k, v)
	}
	return s
}
