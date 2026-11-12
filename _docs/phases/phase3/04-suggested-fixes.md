# Suggested Fixes & Implementation Details

> **Document:** Phase 3 / Document 04  
> **Topic:** Exact Code Modifications to Resolve Active Regressions

---

## Fix 1: Restore Repository Contract in `session_repo.go`

In `src/app/repository/gormauth/session_repo.go`: Remove the SQL `expires_at` pushdown from `ListSessions`.

```diff
diff --git a/src/app/repository/gormauth/session_repo.go b/src/app/repository/gormauth/session_repo.go
index 6a54bd2..e612845 100644
--- a/src/app/repository/gormauth/session_repo.go
+++ b/src/app/repository/gormauth/session_repo.go
@@ -126,7 +126,6 @@ func (r *SessionRepo) ListSessions(ctx context.Context, userID string) ([]models
 	var sessions []models.Session
 	err := gormutil.GetDB(ctx, r.db).
 		Where(sessionsOfUser(userID), "UserID").
-		Where("expires_at > ?", time.Now().UTC()).
 		Find(&sessions).Error
 	if err != nil {
 		return nil, fmt.Errorf("gorm/session: list by user: %w", err)
```

**Verification**: `go test ./src/app/repository/gormauth -count=1` passes 100%.

---

## Fix 2: Session Defaults in `sessionsvc.NewManager`

In `src/app/services/session/manager.go`: Ensure default database persistence is active if unset:

```diff
diff --git a/src/app/services/session/manager.go b/src/app/services/session/manager.go
index c879612..8451f21 100644
--- a/src/app/services/session/manager.go
+++ b/src/app/services/session/manager.go
@@ -67,6 +67,9 @@ func (mgr *Manager) WithOptions(opts ...ManagerOption) { for _, o := range opts
 
 // NewManager builds a Manager; store and hooks may be nil.
 func NewManager(conf config.Session, users repo_interfaces.IUserRepo, sessions repo_interfaces.ISessionRepo, store sec_storage.SecondaryStorage, hooks plugins.HookRegistry, opts ...ManagerOption) *Manager {
+	if !conf.StoreSessionInDatabaseSet && !conf.StoreSessionInDatabase {
+		conf.StoreSessionInDatabase = true
+	}
 	mgr := &Manager{usersRepo: users, sessionsRepo: sessions, secStore: store, conf: conf, hooks: hooks, now: time.Now, generateID: idgen.GenerateID}
 	for _, o := range opts { o(mgr) }
```

**Verification**: `go test ./src/plugins/access-token/test -count=1` passes 100%.

---

## Fix 3: Fix Race Condition in `DefaultHookRegistry.Register`

In `src/plugins/hooks.go`: Remove the unsynchronized slice check:

```diff
diff --git a/src/plugins/hooks.go b/src/plugins/hooks.go
index 213ad11..4f7ba92 100644
--- a/src/plugins/hooks.go
+++ b/src/plugins/hooks.go
@@ -126,9 +126,6 @@ func (h *DefaultHookRegistry) Register(service HookService) {
 	if service == nil {
 		return
 	}
-	if h.services == nil {
-		h.services = make([]HookService, 0)
-	}
 	h.mu.Lock()
 	defer h.mu.Unlock()
 	for _, existing := range h.services {
```

---

## Fix 4: Align `RecordNotFound` to `"Not Found"` & Decouple `errors.New`

1. In `src/common/errors/resp-code-list.go:127`:
   ```diff
   -	RecordNotFound: "data not found",
   +	RecordNotFound: "Not Found",
   ```

2. In `src/app/services/auth/service.go:30`:
   ```diff
   -	ErrDeleteUserDisabled          = autherr.Err(http.StatusNotFound, "NOT_FOUND", "data not found")
   +	ErrDeleteUserDisabled          = autherr.Err(http.StatusNotFound, "NOT_FOUND", "Not Found")
   ```

3. In `src/common/errors/error.go:32`: Decouple `New()` from singleton registration:
   ```diff
   -// New creates and registers a new AuthError. Duplicate codes with differing messages panic.
   +// New creates a new AuthError instance.
    func New(code RespCode, message string, status int) *AuthError {
   -	return Err(status, string(code), message)
   +	return &AuthError{StatusCode: status, Code: code, Message: message}
    }
   ```

---

## Fix 5: Complete `SessionPatch` Direct Mutation

In `src/app/services/session/manager.go`: Instead of converting `SessionPatch` to `map[string]any` via `ToMap()` and calling reflection in `setSessionFields`, mutate the struct fields directly:

```go
func (mgr *Manager) applyPatch(s *dtos.SessionData, patch config.SessionPatch) {
	if patch.ActiveOrganizationID != nil { s.ActiveOrganizationID = patch.ActiveOrganizationID }
	if patch.ActiveOrganizationRole != nil { s.ActiveOrganizationRole = patch.ActiveOrganizationRole }
	if patch.ActiveTeamID != nil { s.ActiveTeamID = patch.ActiveTeamID }
	if patch.DeviceToken != nil { s.DeviceToken = *patch.DeviceToken }
	if patch.DeviceID != nil { s.DeviceID = patch.DeviceID }
	if patch.DeviceName != nil { s.DeviceName = patch.DeviceName }
	if patch.DeviceType != nil { s.DeviceType = patch.DeviceType }
}
```
