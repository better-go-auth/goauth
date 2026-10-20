# Issues, Flaws, and Regressions

> **Document:** Phase 3 / Document 03  
> **Topic:** Analysis of Active Regressions, Flaws, and Design Deficiencies

---

## 1. [CRITICAL] `session_repo.go:ListSessions` Contract Violation

* **File**: [`src/app/repository/gormauth/session_repo.go:127`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/app/repository/gormauth/session_repo.go#L127)
* **Code**:
  ```go
  func (r *SessionRepo) ListSessions(ctx context.Context, userID string) ([]models.Session, error) {
      var sessions []models.Session
      err := gormutil.GetDB(ctx, r.db).
          Where(sessionsOfUser(userID), "UserID").
          Where("expires_at > ?", time.Now().UTC()).
          Find(&sessions).Error
      return sessions, err
  }
  ```
* **Why It Is Wrong**:
  1. The repository contract (`src/app/repository/repotest/contract.go:219`) specifically asserts:
     ```go
     require.Len(t, list, 3, "ListSessions includes expired sessions")
     ```
     Repositories are data-access components; they must return all sessions belonging to a user so background cleanup routines and admin auditors can inspect them.
  2. The business filter to exclude expired sessions from end-users already exists in `sessionsvc.Manager.List`.
* **Impact**: `go test ./src/app/repository/gormauth` fails with `ListSessions includes expired sessions`.

---

## 2. [CRITICAL] `StoreSessionInDatabase` Config Defaults in `NewManager`

* **File**: [`src/app/services/session/manager.go:67`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/app/services/session/manager.go#L67) and [`src/config/config.go:127`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/config/config.go#L127)
* **Code**:
  ```go
  func NewManager(conf config.Session, users repo_interfaces.IUserRepo, sessions repo_interfaces.ISessionRepo, store sec_storage.SecondaryStorage, hooks plugins.HookRegistry, opts ...ManagerOption) *Manager {
      mgr := &Manager{usersRepo: users, sessionsRepo: sessions, secStore: store, conf: conf, hooks: hooks, now: time.Now, generateID: idgen.GenerateID}
      ...
  ```
* **Why It Is Wrong**:
  1. In Phase 2, `StoreSessionInDatabase` was migrated from `*bool` to `bool`. In Go, the zero value of `bool` is `false`.
  2. While `AuthConfig.SetDefaults()` has a rule to set `StoreSessionInDatabase = true` if `!StoreSessionInDatabaseSet`, constructing `sessionsvc.NewManager(config.Session{ExpiresIn: ...})` directly (such as in `access_token_test.go:57`) bypasses `AuthConfig.SetDefaults()`.
  3. Consequently, `NewManager` treats database storage as disabled (`StoreInDatabase() == false`). Sessions are written only to cache, and later calls to `SessionRepo.FindSessionByID` fail with record not found.
* **Impact**: `src/plugins/access-token/test` fails on `ResetToken` with `[INVALID_TOKEN] Invalid token`.

---

## 3. [HIGH] Error Code Registry Divergence & Panic Risk

* **File**: [`src/common/errors/resp-code-list.go:127`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/common/errors/resp-code-list.go#L127) and [`src/app/services/auth/service.go:30`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/app/services/auth/service.go#L30)
* **Code**:
  ```go
  // In resp-code-list.go:
  RecordNotFound: "data not found",

  // In service.go:
  ErrDeleteUserDisabled = autherr.Err(http.StatusNotFound, "NOT_FOUND", "data not found")
  ```
* **Why It Is Wrong**:
  1. The canonical Better Auth HTTP 404 message is `"Not Found"`.
  2. In commit `07bba59`, `service.go:30` was changed to `"data not found"` solely to circumvent a startup panic in `registry.Err`, leaving the non-standard message in place.
  3. `errors.New()` delegating directly to `registry.Err()` means that any dynamic message supplied at runtime for an existing code will panic the application.
* **Impact**: Divergence from Better Auth error contracts and crash risk on dynamic error messages.

---

## 4. [MEDIUM] Data Race in `DefaultHookRegistry.Register`

* **File**: [`src/plugins/hooks.go:126`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/plugins/hooks.go#L126)
* **Code**:
  ```go
  func (h *DefaultHookRegistry) Register(service HookService) {
      if service == nil {
          return
      }
      if h.services == nil {
          h.services = make([]HookService, 0)
      }
      h.mu.Lock()
      defer h.mu.Unlock()
      ...
  ```
* **Why It Is Wrong**:
  The check `if h.services == nil` and slice allocation occur **outside** `h.mu.Lock()`. If multiple plugins or goroutines register hooks concurrently during initialization, this causes a data race. In Go, appending to a `nil` slice is safe without pre-allocation.
* **Impact**: Concurrency race under `go test -race`.

---

## 5. [MEDIUM] Process-Global State in `models/tables.go`

* **File**: [`src/models/tables.go:20-48`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/models/tables.go#L20-L48)
* **Code**:
  ```go
  var (
      tableMu        sync.RWMutex
      tablePrefix    string
      tableOverrides = map[string]string{}
  )
  ```
* **Why It Is Wrong**:
  Table prefixes and overrides are stored in package-global variables. In multi-tenant applications or parallel integration test runners where different `GoAuth` instances require different table prefixes, calling `SetTableNames` mutates state globally across all instances.
* **Impact**: Inability to support isolated multi-tenant instances within a single Go process.

---

## 6. [MEDIUM] Reflection in `sessionsvc.Manager.Update`

* **File**: [`src/app/services/session/manager.go:418-439`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/app/services/session/manager.go#L418-L439)
* **Code**:
  `UpdatePatch(ctx, swu, patch)` delegates to `Update(ctx, swu, patch.ToMap())`, which runs `setSessionFields(&out.Session, data)` using reflection.
* **Why It Is Wrong**:
  * `setSessionFields` only handles `string` and `*string` fields; passing non-string values returns `cannot set %s to %T`.
  * It incurs reflection overhead on every session update.
* **Impact**: Type-safety bypass and performance penalty on session updates.

---

## 7. [MEDIUM] Incomplete Team & Role Wiring in `plugins/org`

* **File**: [`src/plugins/org/services/`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/plugins/org/services/) and [`src/plugins/org/adapters/huma/`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/plugins/org/adapters/huma/)
* **Issue**: Models and repositories for `Team`, `TeamMember`, and `OrganizationRole` exist, but no services or Huma REST endpoints expose them.
* **Impact**: Feature incompleteness relative to the Better Auth organization specification.
