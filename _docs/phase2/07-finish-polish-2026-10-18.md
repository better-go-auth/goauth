# Finish polish (2026-10-18) - not committed

> Completes the 6 remaining items from `06-breaking-cleanup`: StoreSession sentinel, SessionPatch, cookie injection, per-manager ID generator, org wiring status, vet/tests. Not committed - review then `git add -A && git commit`.

## 1. StoreSessionInDatabaseSet (DONE)

**Before:** `config.go:SetDefaults()` used `if ExpiresIn==0 && !StoreSessionInDatabase` to default to `true`. Second call or cache-only caller who set `false` before `SetDefaults` got flipped back.

**After:**
- `src/config/session-config.go` - added `StoreSessionInDatabaseSet bool`. `StoreInDatabase()` unchanged.
- `src/config/options.go` - added `func WithStoreInDatabase(s *Session, v bool)` helper (`Set + Set=true`). Either file works (same package).
- `src/config/config.go` - sentinel is now `if !StoreSessionInDatabaseSet && !StoreSessionInDatabase`. Explicit `WithStoreInDatabase(&cfg.Session, false)` or `{StoreSessionInDatabase:false, StoreSessionInDatabaseSet:true}` survives.
- `src/app/services/session/manager_test.go:TestSecondaryStorageOnly` - updated to `{StoreSessionInDatabase:false, StoreSessionInDatabaseSet:true}` so it actually tests cache-only (was silently flipped to `true` via `ExpiresIn==0`).
- `src/app/services/auth/service.go` - fixed `ErrDeleteUserDisabled` message `"Not Found"` -> `"data not found"` so it matches `RecordNotFound.Msg()` and doesn't panic on duplicate `NOT_FOUND` registration (found via `go vet`/`go test`).

**Migration:** callers who previously did `cfg.Session.StoreSessionInDatabase = false` before `SetDefaults` must now use `config.WithStoreInDatabase(&cfg.Session, false)` or set `StoreSessionInDatabaseSet=true`.

## 2. SessionPatch typed update (DONE)

**Before:** `Manager.Update(ctx, swu, map[string]any)` with `setSessionFields` reflection; `Update` TODO.

**After:**
- `src/config/session-config.go` - added `type SessionPatch struct {ActiveOrganizationID, ActiveOrganizationRole, ActiveTeamID, DeviceToken, DeviceID, DeviceName, DeviceType *string}` + `func (sp SessionPatch) ToMap() map[string]any`.
- `src/app/services/session/manager.go` - added `func (mgr *Manager) UpdatePatch(ctx, swu, patch config.SessionPatch) (*SessionWithUser, error)` delegating to `Update` via `ToMap()`. Keeps `Update(map)` for compat/backlog; typed callers migrate to `UpdatePatch`.
- `src/app/services/interfaces/session-interface.go` - added `UpdatePatch` to `ISessionManager`; imported `config`.

**Remaining:** `src/app/services/auth/session.go:UpdateSession` (HTTP handler) still builds `map[string]any` from `UpdatableFields`; when ready, add `SessionPatch` mapping there and deprecate `map` overload. `setSessionFields` reflect stays until then.

## 3. Cookie injection via http.Cookie + IsToken guard (DONE)

**Before:** `r.Header.Set("Cookie", name+"="+val)` raw concat in `access-token` (2 sites) and `bearer` (wrapped + http.Request). No `IsToken` validation before signing/injecting; string-concat not using `http.Cookie`.

**After:**
- `src/plugins/access-token/access_token.plugin.go` - added imports `net/http` + `idgen`; added helpers `injectCookieHeader(r, name, signedVal)`, `containsCookie`, `containsSubstr`, `indexOf`, `splitCookieHeader`, `trimSpace` (uses `http.Cookie{Name, Value, Path:"/"}.String()` then strips to `name=value`; checks existing header). Both JWT + raw fallback now `if !idgen.IsToken(tok/raw) { skip or IsToken guard }` + `injectCookieHeader`. Second site (raw bearer fallback) also now via `injectCookieHeader` instead of direct `Header.Set`.
- `src/plugins/bearer/bearer.plugin.go` - added imports `net/http` + `idgen`; added `bearerCookieValue(name, signedVal)` (touches `http.Cookie{}.String()` for escaping validation, returns `name=value`). `signedCookieVal` now only created when `hasBearer && idgen.IsToken(bearerToken)` else `hasBearer=false`. Both `wrapped.injectedCookie` and `r.Header.Set` now via `bearerCookieValue`.
- Fixed `indexOf` vet error `i+len(s)-len(sub)+1` non-boolean -> `i <= len(s)-len(sub)`.

**Note:** signed cookie value itself is `token.sig` not `IsToken` shaped, so bearer validates raw `bearerToken` before signing; access-token validates raw `tok`/`raw` before signing.

## 4. Per-manager ID generator (DONE)

**Before:** global `models.NewID -> idgen.GenerateID` + deleted `SetIDGenerator`; `Advanced.Database.GenerateID` ignored. `Manager.Create` used `models.NewID()` unconditionally.

**After:**
- `src/app/services/session/manager.go` - added `generateID func() string` field; new option `WithGenerateID(func()string)`; `NewManager` defaults to `idgen.GenerateID`; `Create` now `if mgr.generateID != nil {id=mgr.generateID()} else idgen.GenerateID()`.
- `goauth.go` - `SetupGoAuth` now `if opts.Advanced.Database.GenerateID != nil {sessOpts = append(sessOpts, WithGenerateID(...))}` and passes to `NewManager`.
- Other repos (`gormauth/user_repo`, `session_repo`, `account_repo`, `verification_repo`, org `team/member/invitation`) still use `models.NewID()` / `BeforeCreate` fallback - per-repo override would need `GormRepos` threading; session path covers the hot path. Documented as limitation (callers can pass explicit `ID` in create inputs if custom scheme needed).

## 5. Org teams wiring - status (PARTIAL, backlog remains)

What exists (from `05-phase2-round2`):
- Models `Team`, `TeamMember`, `OrganizationRole`, repos `TeamRepo/TeamMemberRepo/OrganizationRoleRepo`, migrator `AutoMigrate`, config `Teams`/`DynamicAccessControl`, constants `ModelTeam` etc., session `activeTeamId` claim.

Still TODO (tracked, not done here):
- Services `ITeamService`/`IOrganizationRoleService` (caps `maximumTeams`, `maximumMembersPerTeam`, `allowRemovingAllTeams`, `invitation.teamId` validation).
- `RequireOrgMember` permission evaluation: static vs `organizationRole.permission` JSON behind `DynamicAccessControl.Enabled`.
- Huma routes `team`/`organizationRole` CRUD 404 when disabled; `activeTeamId` propagation to resolver/claims.
- Plan doc `04-plan/NN-org-teams.md` + extended `src/plugins/org/test` (team/role happy paths + disabled 404s).

## 6. Verify (DONE)

- `GOCACHE=$TMPDIR/gocache go vet ./...` - passes.
- `GOCACHE=$TMPDIR/gocache go test ./src/app/services/session ./src/app/services/auth ./src/tests/compat -count=1` - 3/3 pass (`session` 0.053s, `auth` 4.6s, `compat` 4.1s).
- `src/...` (non-docker) e2e failures are docker-only (`TestAuthE2E`, `TestProfileE2E`, `TestSessionE2E`, `TestOrgE2E` require `docker.sock`); 1 real fix was `NOT_FOUND` duplicate + `StoreSessionInDatabase` test.
- `src/app/repository/gormauth/session_repo.go:ListSessions` now only `Where("expires_at > ?", ...)` - `LENGTH(token)=32` removed per request; `Manager.List` retains `IsToken+ExpiresAt` safety net for memory repo. DB is `varchar(255)` (`size:255`), so `32` is data invariant, not DDL.
- `git status` not committed - 11 files, 135+/34- (`goauth.go`, `session_repo.go`, `service.go`, `session-interface.go`, `manager.go`, `manager_test.go`, `config.go`, `options.go`, `session-config.go`, `access_token.plugin.go`, `bearer.plugin.go`). Review diff then commit.

## What remains / next steps

1. **SessionPatch full cutover** - when breaking `Update` API: deprecate `Update(map)`, make `auth/service.go:UpdateSession` build `SessionPatch` from `UpdatableFields` instead of `map`, keep `setSessionFields` until callers migrate.
2. **Per-repo ID generator** - if `Advanced.Database.GenerateID` should affect user/org/team/verification IDs too, thread `GenerateID` into `gormauth.NewAuthRepos`/`GormRepos` and override `BeforeCreate` or set `ID` before `Create`.
3. **Org teams services/routes** - see 5 above (`05-phase2-round2` next).
4. **`LENGTH(token)` removal verified** - done; no further `WHERE LENGTH` remains.
5. **AdditionalFields (generic columns)** - if `additionalFields` like better-auth needed, choose `ExtraAttrs JSONMap` vs `ALTER TABLE ADD COLUMN` vs typed options (see `_docs/phase2/01` backlog).
