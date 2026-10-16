# Phase 2 — Improvements & Fixes (how to do each)

> Branch: `feat/improvements-1-10` (2 commits on top of `feat/sid-token-index` at time of writing).
> Active plan this file implements: `/home/k/.claude/plans/tranquil-shimmying-wozniak.md` (items 1–10).
> Each item is bisectable, `go vet` clean, and is a single commit unless noted.

Status legend: **Done** = shipped on branch, **Partial** = code changed but follow-ups remain, **Todo** = spec'd, not yet implemented.

---

## 1. `context.Background()` leaks -> `SetupGoAuth(ctx, ...)`

**Status: Done** — `194716a`

**Problem:** `goauth/goauth.go` used `context.Background()` inside setup, so cancellations/timeouts from callers never propagated to `Migrate`, plugin `Init`, and plugin `Migrator.Migrate`. Tests also leaked.

**Fix:**
- Signature is now `func SetupGoAuth(ctx context.Context, api huma.API, opts GoAuthOptions) (*GoAuth, error)` with `if ctx == nil { ctx = context.Background() }` fallback for compat.
- Thread `ctx` to: `migrator.Migrate(ctx)`, `initCtx.Ctx = ctx`, phase-2 `mig.Migrate(ctx)`, and ensure `models.SetTableNames` runs before `gormauth.NewAuthRepos` if `*gorm.DB` already cached.
- Updated all 8 in-repo call sites: `src/tests/helpers/setup.go`, `src/tests/compat/server.go`, `src/tests/auth/*.go`, `src/plugins/*/test/*.go`, `src/example/main.go`, `src/example/example_test.go` to `SetupGoAuth(context.Background(), api, opts)` (or `t.Context()` where desired).
- Missing `import "context"` added to `src/tests/compat/server.go` and `src/plugins/bearer/test/bearer_test.go` via `$TMPDIR` patch scripts (read-only `/tmp` sandbox workaround).

**Files:** `goauth/goauth.go:90`, `src/tests/compat/server.go:88`, `src/tests/helpers/setup.go:207`, `src/plugins/bearer/test/bearer_test.go`, `src/example/main.go:137`

**How to finish/verify:**
```bash
GOCACHE=$TMPDIR/gocache go -C goauth vet ./...
grep -rn "context.Background()" goauth --include="*.go"  # only the nil-fallback in goauth.go should remain
```

---

## 2. Typed `InitContext` (replace `Extras map[string]any`)

**Status: Done** — `194716a`

**Problem:** `Extras map[string]any` with string keys (`"db"`, `"sessionManager"`, `"secondaryStorage"`, `"cookieManager"`) required unsafe type assertions in every plugin.

**Fix:**
- `src/plugins/plugins-interface.go` now has typed fields alongside the escape hatch:
  ```go
  type InitContext struct {
      Ctx              context.Context
      Api              huma.API
      Config           config.AuthConfig
      TxManager        interfaces.ITransactionManager
      SessionManager   svcint.ISessionManager
      IAuthSvc         svcint.IAuthService
      IAuthRepos       repo_interfaces.IAuthRepos
      MiddleWare       *middleware.AuthMiddleware
      Authenticator    authenticator.AuthenticateFunc
      Hooks            HookRegistry
      SecondaryStorage sec_storage.SecondaryStorage
      DB               *gorm.DB
      CookieManager    *cookies.Manager
      Extras           map[string]any // kept for truly custom needs
  }
  ```
- `goauth/goauth.go` populates `DB: opts.Conn, CookieManager: cookieMgr` and still fills `Extras` for compat.
- `src/plugins/access-token/access_token.plugin.go` and `src/plugins/jwt/jwt.plugin.go` prefer `ictx.DB` / `ictx.CookieManager` / `ictx.SecondaryStorage` / `ictx.SessionManager` with `Extras` fallback + deprecation path (one release).
- Import ordering touched (`context` first in `plugins-interface.go`).

**How to finish:** Remove the `Extras["db"]` fallback branches after one release; `go vet` will flag remaining `Extras[` uses.

---

## 3. Revocation prefix unification

**Status: Done** — `18f100a` (plus `194716a` scaffolding)

**Problem:** Three prefixes in flight: `blacklist:` (legacy), `revoked:session:`, `blacklisted:token:` typo, and `blacklist:token:`. Writes and reads disagreed.

**Fix:**
- New `src/providers/sec-storage/keys.go` canonicalises:
  ```go
  const SidPrefix = "sid:"
  const ActiveSessionsPrefix = "active-sessions-"
  const RevokedSessionPrefix = "revoked:session:"
  const RevokedTokenPrefix = "blacklist:token:"
  const LegacyBlacklistPrefix = "blacklist:"
  ```
- `src/providers/revocation_store.go:IsRevoked` checks `RevokedSessionPrefix` then `LegacyBlacklistPrefix` (compat read), then DB fallback when `CheckRevocation`.
- `src/providers/revocation_store.go:IsTokenBlacklisted` uses `RevokedTokenPrefix`.
- `src/common/middleware/funcs.go:KeyValRevocationStore` uses the same constants; typo `blacklisted:token` fixed and compat read kept.
- `src/plugins/access-token/services/serv.session.go:BlacklistSession` writes `sec_storage.RevokedSessionPrefix+sid`.
- `src/plugins/access-token/access_token.plugin.go` revocation check reads both prefixes; `src/common/middleware/middleware_test.go` updated to import `sec_storage` alias.

**How to verify:** `grep -rn "blacklist:" goauth --include="*.go"` should show only the compat read in `revocation_store.go` and `funcs.go` plus the constant definition; no `blacklist:` writes remain. `grep -rn "RevokedSessionPrefix" goauth` should show all writers.

---

## 4. Stop swallowing cache errors

**Status: Partial** — `18f100a` added `slog.Warn` at key points; more sites remain

**Problem:** Many `SecondaryStorage` errors were discarded with `_ = cache(...)` or `if _, exists, _ := store.Get(...)`, hiding Redis outages and making debugging impossible.

**Fix so far:**
- `src/app/services/session/manager.go` — `Get` backfill failure now `slog.Warn("sessions: cache backfill failed", "err", err, "token", ...)`.
- `src/app/services/session/manager-sec-store.go` — `trackActive` race documented with `NOTE:` comment; `saveActive`/`untrackActive`/`DeleteUserSessions` warn on `Set`/`Delete` failures; `RefreshUser` warns on cache failure.
- `src/app/adapters/huma/session_claims.go` — extra DB lookups for `Role`/`ActiveOrganizationRole` log at `slog.Debug` and fall back to snapshot; comment notes roles may be stale without DB.

**What is left:**
- `src/app/services/session/manager.go:Refresh`, `Rotate`, `Update`, `List` still use `fromStore` error correctly but some backfill paths still ignore errors silently.
- `src/plugins/access-token/access_token.plugin.go:221,308` middleware path should warn on `GetBySID` cache miss vs error distinction.
- Add `slog.Warn` with `err` attribute on every `Set`/`Delete`/`GetAndDeleteCtx` failure; consider an `otel` counter `cache_error` if otel is configured, else log-only.
- Manual verification: run with Redis down — `Get` should still return DB, with warnings visible in logs.

---

## 5. `Authenticate()` JSON errors + `looksLikeJWT`

**Status: Done** — `18f100a`

**Problem:** Auth failures returned `403` plaintext `Token Not Valid`; callers expecting better-auth JSON `{"code": "...", "message": "..."}` could not parse it. `isJWT` name was vague. `Authorize`/`AuthorizeOrg` duplicated a 3-way type switch.

**Fix:**
- Renamed `isJWT` → `looksLikeJWT` (`strings.Count(tok, ".")==2`), kept `isJWT` as deprecated alias.
- Added `writeAuthError(ctx huma.Context, status int, msg string)` helper:
  ```go
  func writeAuthError(ctx huma.Context, status int, msg string) {
      ctx.SetStatus(status)
      ctx.SetHeader("Content-Type", "application/json")
      _ = json.NewEncoder(ctx.BodyWriter()).Encode(map[string]any{"message": msg, "code": status})
  }
  ```
- All `ctx.SetStatus(http.StatusForbidden); ctx.Write([]byte("Token Not Valid"))` replaced with `writeAuthError(ctx, http.StatusUnauthorized, "Token Not Valid")`.
- Missing/invalid token → 401, revoked → 401, not authorized → 401 via `Authorize` (note: better-auth uses 401 for auth, 403 for forbidden — follow-up may map to 403 via `Authorize`).
- Added `claimsFromCtx` helper to DRY the 3× type switch in `Authorize`/`AuthorizeOrg`.

**Follow-up:** Map to `autherr.ErrUnauthorized` / `autherr.ErrSessionRevoked` with `RespCode` for wire compat if clients match error codes (golden files in `src/tests/compat/golden/*.json` expect JSON). Check `tests/compat` after change.

---

## 6. Architecture cleanup

**Status: Partial**

### 6a. Split `Manager` (440 LOC)

**Todo.** Create `src/app/services/session/manager_update.go` and move `Update` + `setSessionFields` there. Introduce:
```go
type SessionPatch struct {
    ActiveOrganizationID   *string `json:"activeOrganizationId"`
    ActiveOrganizationRole *string `json:"activeOrganizationRole"`
    DeviceToken            *string `json:"deviceToken"`
    // etc. from DefaultUpdatableSessionFields
}
```
Keep `map[string]any` overload for one release with deprecation, or remove immediately (only 2 call sites: `auth/session.go:99`, `access-token/serv.session.go:221`).

### 6b. Dead code

**Done (partial):** Deleted `src/config/cookie.go` (unused `type Cookie`) and `src/config/z_auth-config.go` (100% comments). Commented blocks in `goauth.go:167-175,240-246` removed. Remaining: decide on `RouteDescriptor` — **delete** `Routes()` from `Plugin` interface (all 6 plugins return `nil`) and keep `SetupHumaRoutes` as the contract; or implement adapter loop in `goauth.go`.

### 6c. `GoAuth` accessors

**Todo.** Add `// Read-only after SetupGoAuth; do not mutate` doc to `GoAuth` fields. Fix typo `*providers.IProviderS` → `*providers.Providers` (or keep alias with deprecation).

### 6d. `StoreSessionInDatabase *bool` → `bool`

**Todo.** Field `Session.StoreSessionInDatabase *bool` forces nil-checks via `StoreInDatabase() bool`. Change to `bool` with `DefaultStoreInDatabase = true`. In `SetDefaults`, `if !opts.Session.StoreSessionInDatabaseSet { opts.Session.StoreSessionInDatabase = true }` or drop pointer and default to true. Update `storeInDB()` to `return mgr.conf.StoreSessionInDatabase`. Tri-state workaround: add `StoreSessionInDatabaseSet bool` if explicit false must be distinguishable from unset.

### 6e. Global `SetIDGenerator`

**Todo.** Keep `models.SetIDGenerator` for compat but add `Manager` option `WithIDGenerator(func() string)` and prefer instance field. Global `var idGenerator` races in tests; instance field eliminates it. Document and suggest `WithIDGenerator` for tests.

---

## 7. Data-layer fixes

| Sub-item | Status | Detail |
|---|---|---|
| **D1** account `NotFoundErr` | **Done** `18f100a` | `src/app/repository/gormauth/account_repo.go:43,57` now returns `loc_errors.NotFoundErr("gorm/account: not found")` matching `user_repo:43`, `session_repo:60`. |
| **D2** verification Tx | **Done** `18f100a` | `src/app/repository/gormauth/verification_repo.go:30-45` now `db := gormutil.GetDB(ctx, r.db); db.WithContext(ctx).Transaction(...)` respecting `TxKey`. |
| **D3** List pushdown | **Todo** | `src/app/services/session/manager.go:414-442` fetches all sessions then filters in Go. Add SQL `WHERE expires_at > now()` and pagination param to `ListSessions`; use `LENGTH(token)=32` for SQLite compat as pre-filter, keep `IsToken` in Go. |
| **D4** DeleteVerificationsByValue | **Todo** | Keep Go `HasPrefix` for correctness (escaping), but add `WHERE value = ? AND identifier LIKE ? ESCAPE '\'` pre-filter with proper escape of `%_\\`. |
| **D5** Expiry UTC | **Done** (verified) | `manager.go:167` uses `mgr.now().UTC()` already; no change needed. |
| Origin regex cache | **Done** `18f100a` | `src/providers/origin/origin.go` precompiles wildcard regexes into `map[string]*regexp.Regexp` at `New()` time; `Matches` uses `matchesCached`. |
| `trackActive` race | **Partial** | Added `NOTE:` comment about read-modify-write without `WATCH`/Lua; last-write-wins is acceptable for now. Lua if Redis, else documented. |

---

## 8. Security hardening

| Sub-item | Status | Detail |
|---|---|---|
| **S2** Token plaintext | **Deferred** | Needs migration to `SHA256(token)` at rest. Add `TODO(security): hash tokens at rest` and track issue. No code change in this batch. |
| **S4** Bearer `RequireSignature` | **Todo** | `src/plugins/bearer/bearer.plugin.go:211` defaults `false`, allowing raw tokens. Add warning log when `RequireSignature==false`; document. Flip default to `true` as breaking change later. |
| Cookie rotation | **Todo (doc)** | Document that `Secret` rotation invalidates all sessions; point to `authcrypto.SecretKeys` envelope for future. |
| Key derivation | **Todo (doc)** | Validate `Secret >=32` in `Validate()` already warns; escalate to error in `compat` mode. Add `HKDF` note. |
| Header injection | **Todo** | `src/plugins/access-token/access_token.plugin.go:358` does `Header.Set("Cookie", ...+tok)`. Validate `tok` via `IsTokenLike` before injection (reuse `isTokenLike` via shared `sec-storage/keys.go` helper). |
| Rate limit | **Todo** | Add `RateLimiter` interface hook in `src/common/middleware` (no-op default), wire via `GoAuthOptions.RateLimiter`. Document integration point. No behavior change now. |

---

## 9. Errors & logging

**Status: Partial** — cosmetic fixes done

- **Two registries:** Keep `registry.go:Err()` as canonical. Make `resp-code.go:New()` call `Err()` (registered) instead of raw struct. Consolidate `errorText` map — ensure every `RespCode` in `resp-code-list.go` has an entry or uses fallback. Fix cosmetic: `" User Created"` leading space and `" please..."` lowercase — **done** in `resp-code-list.go`.
- **Logger:** Gate ANSI colors behind `TERM`/`NO_COLOR` or remove; ensure `slog.Attr` actually logged. Unify to `slog` JSON handler — remove `logger.LogTrace` wrapper or make it `slog.Debug`. **Todo.**
- **Wrapping:** Standardize `fmt.Errorf("...: %w", err)` chain in repos/services. **Todo** (lint `errorlint`).

---

## 10. Tests & DX

**Status: Partial** — harness improved

- **`log.Fatalf` → `t.Fatalf`:** `src/tests/helpers/setup.go:103,114,130,136,140,165,170,189,194,229` — change to `t.Fatalf` (need `*testing.T` param, already have `t`). For container failures, `t.Skip` if Docker unavailable instead of panic. **Todo** (partial `t.Helper()` added).
- **`panic` in `doJSON`:** Return `(nil, err)` and `t.Helper(); t.Fatalf`. **Todo.**
- **Missing `t.Helper()`:** Added to `SetupTestEnv`, `doJSON`, `TestEnv` helpers. **Done** (`18f100a`).
- **golangci-lint CI:** Add `.golangci.yml` with `contextcheck, errcheck, bodyclose, noctx` if not present. **Todo.**
- **Clock:** Expose `ManagerOption` `WithClock(func() time.Time)` properly; tests use `mgr.now = fn` hack — replace with option. **Todo.**
- **SecureCookies cache:** `src/config/options.go:64,72` — compute `secure bool` and `cookieDomain string` in `SetDefaults()` and store on `AuthConfig` (e.g., `cachedSecure *bool`), avoid `url.Parse` per request. **Todo.**
- **Observability:** Add otel counters `cache_hit/miss/dbfallback/sid_hit` (optional, log fallback if otel not configured). **Todo.**

---

## Commit order already used / remaining

Shipped:
1. `feat: thread ctx through SetupGoAuth` — Done
2. `feat: typed InitContext DB/CookieManager` — Done (same commit as 1, `194716a`)
3. `fix: unify revocation prefix` — Done (`18f100a`)
4. `fix: surface cache errors + warn + account NotFoundErr + verification Tx` — Done (combined in `18f100a`)
5. `fix: middleware JSON errors + looksLikeJWT` — Done (`18f100a`)

Remaining, in order:
6. `refactor: split session manager + typed SessionPatch` (6a)
7. `chore: remove RouteDescriptor + GoAuth accessors` (6b/6c/6d/6e)
8. `refactor: origin regex cache + SecureCookies cache + manager List pushdown` (7 — origin done, List/SecureCookies remain)
9. `chore: error registry consolidation + logger` (9)
10. `test: harness t.Fatalf + helpers + lint config` (10)

Each commit must be `GOCACHE=$TMPDIR/gocache go -C goauth vet ./...` clean and keep `src/tests/compat` golden tests green.

## Verification

```bash
GOCACHE=$TMPDIR/gocache go -C goauth vet ./...
GOCACHE=$TMPDIR/gocache go -C goauth test ./src/tests/compat ./src/app/services/session ./src/providers/origin -count=1 -run Test -timeout 60s
# manual:
go -C goauth run ./src/example & # boots, GET /api/auth/ok 200
# curl sign-up then Bearer JWT after sign-out -> 401
```
Container tests optional: `go -C goauth test ./src/tests/helpers -run TestSetup -count=1` with Docker.
