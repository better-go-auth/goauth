# 03 – Done: remove `session.session_id`

## Why it exists today

One table holds two kinds of session:

| kind | `id` | `session_id` | `token` |
|---|---|---|---|
| legacy JWT (access/refresh) | random ULID | the JWT `sid` claim | SHA-256 of the refresh JWT |
| better-auth (cookie) | random ID | = `token` | raw 32-char token |

`session_id` is the lookup key for the JWT `sid`. It is also how the code tells the two kinds apart
(`isTokenSession`: `token == session_id`).

## Where it is used

| area | file | use |
|---|---|---|
| Legacy create / refresh | `app/core/session/session.service.go` `CreateSession` | sets `SessionId: sid`; upsert re-uses the same sid on refresh |
| Upsert | `app/repository/gormauth/session_repo.go` `UpsertSession` | `ON CONFLICT (session_id)` |
| Lookups | `session_repo.go` `GetSessionByID`, `GetSessionBySessionID`, `GetSessionByToken`, `UpdateSession`, `DeleteSession`, `ListSessions` (filter) | `session_id = ?` (often `OR id = ?` / `OR token = ?`) |
| Refresh / logout | `app/core/auth/auth.service.go` (refresh, logout, revoke) | `GetSessionBySessionID(claims.SessionID)`, `DeleteSession(session.SessionId)` |
| Revocation check | `providers/revocation_store.go` `gormSessionChecker` | `WHERE session_id = ?` |
| Opaque-token auth | `providers/authenticator/gorm-lookup.go` | `session_id = ? OR token = ?` |
| Session list / revoke-all | `app/core/session/session.service.go` `DeleteAllUserSessions`, `app/core/session/session.handler.go` | `s.SessionId` → KV `blacklist:<sid>`, hooks |
| Admin | `plugins/admin/repository/gorm/admin_session.go` `RevokeUserSession`, `GetSessionByToken`; `plugins/admin/services/serv.session.admin.go` | `session_id = ?` for "session token" |
| Cookie sessions | `sessions/manager.go` | sets `SessionId: tok`; `Get` uses `GetSessionBySessionID(tok)`; `Delete`/`Refresh` pass the token as "session id"; `isTokenSession` |
| Response DTO | `models/dtos/response_dto.go` `SessionToData` | returns `SessionId` as `token` (leaks the sid for legacy sessions) |
| Tests | `tests/auth/custom_repo_test.go` (mock keyed by SessionId), `session_fixes_test.go`, `setup_test.go`, `sessions/manager_test.go`, `plugins/hooks_test.go` | |

## Target

- `id` is the only session identifier.
  - Legacy JWT `sid` = `session.id`.
  - The KV keys (`blacklist:<id>`) and hooks (`TriggerSessionRevoked(id)`) use it too.
- `token` is the only thing a client ever presents for cookie/opaque sessions. Lookups are `WHERE token = ?`
  (hashed first when `Session.HashTokens` is on).
- The two kinds are told apart by **token format**, not by an extra column:
  - a better-auth token is 32 characters `[A-Za-z0-9]` (`idgen.GenerateToken`);
  - a legacy row's token is 64-char hex.
  - The cookie path rejects anything that isn't a valid raw token before querying, so a leaked refresh hash can't be replayed as a cookie.

## Steps

### 1. Key legacy sessions by `id`
- `session.service.go` `CreateSession`: set `Base{ID: sessionId}` instead of `SessionId: sessionId`.
  - Callers already generate the sid: login (`auth.service.go`), impersonation (`serv.session.admin.go`), set-active-org (`serv.org.go`).
- `UpsertSession`: change the conflict target to `id`. Refresh (`auth.service.go`, same `claims.SessionID`) then updates the same row.

### 2. Split the repository API by key
Replace the ambiguous methods in `repo_interfaces/session.repo.go`:

| now | becomes |
|---|---|
| `GetSessionBySessionID(sid)` | `GetSessionByID(id)` (`WHERE id = ?`) |
| `GetSessionByToken(tok)` (`session_id OR token`) | `GetSessionByToken(tok)` (`WHERE token = ?`) |
| `UpdateSession(sessionID, …)` (`session_id OR id`) | `UpdateSession(id, …)` |
| `DeleteSession(sessionID)` (`session_id OR id`) | `DeleteSession(id)` + `DeleteSessionByToken(tok)` |
| `SessionFilter.SessionId` | removed (`SessionFilter.ID` already exists) |

Update the gorm implementation, the admin repo (`RevokeUserSession`/`GetSessionByToken` → `token = ?`),
the revocation checker (`id = ?`) and `authenticator/gorm-lookup.go` (`token = ?`).

### 3. Cookie session manager
- `Create`: drop `SessionId`.
- `Get(tok)`: validate the format (`idgen.IsToken(tok)`: 32 chars, alphanumeric), then `GetSessionByToken`.
  Remove the `s.Token != tok` check and `isTokenSession`.
- `Refresh`: `UpdateSession(sw.Session.ID, …)`.
- `Delete(tok)`: `DeleteSessionByToken(tok)`.
- `List`: return every live session of the user. For rows whose token is not a raw token (legacy), clear `token`
  in the response so the refresh hash is never exposed.

### 4. Legacy JWT paths
- `auth.service.go` refresh/logout/revoke: `GetSessionByID(claims.SessionID)`, `DeleteSession(session.ID)`.
- `session.service.go` `DeleteAllUserSessions` and `session.handler.go`: `s.ID` for the KV blacklist key and hooks.
- `serv.session.admin.go`: `DeleteSession(session.ID)`.

### 5. Responses
- `SessionToData`: `Token` = `s.Token` only when it is a raw token, otherwise empty. `ID` = `s.ID`.
- `compat.SessionFromModel`: same rule.

### 6. Model and tests
- Delete `Session.SessionId` and its `uniqueIndex`. Drop the column, or recreate the database (existing DBs are out of scope).
- Tests:
  - `custom_repo_test.go` mock: key by `ID`; add `DeleteSessionByToken`.
  - `session_fixes_test.go` / `setup_test.go`: `WHERE id = ?`, `Session{Base: models.Base{ID: sid}}`.
  - `manager_test.go`: the legacy row has `ID: "legacy-id"` and a 64-hex token. Assert that `Get` with that token returns nil.
  - `hooks_test.go`: `session.ID`.
- New test: present a legacy row's stored token as a cookie and expect 401.

## After this (breaking checklist in [02-steps.md](02-steps.md))

When the JWT flow becomes a plugin on top of better-auth sessions (refresh token = session token,
access JWT `sid` = `session.id`), there is only one kind of session left. The token-format check then only
validates input, and the "legacy row" handling in `List` / `SessionToData` can be deleted.
