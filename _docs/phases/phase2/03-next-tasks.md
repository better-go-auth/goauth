# Phase 2 — Next tasks (prioritized)

> Branch: `feat/improvements-1-10`. This file is the actionable queue derived from `01-improvements-and-fixes.md` + `02-what-is-left-from-phase1.md`.
> Each task is sized Small / Medium / Large and ordered by dependency. Pick the first unfinished task; do not skip ahead unless explicitly noted.

## Queue

### 1. Finish the `feat/improvements-1-10` branch (M)

Complete items 6a, 6c–6e, 7 D3/D4, 8 S4/header-injection/rate-limit hook, 9 logger/wrapping, 10 harness/lint/clock/SecureCookies/otel from `01-improvements-and-fixes.md`.

Suggested commit order (each `go vet` clean, golden tests green):

| Order | Commit | Covers |
|---|---|---|
| 1 | `refactor: split session manager + typed SessionPatch` | 6a |
| 2 | `chore: remove RouteDescriptor, document GoAuth, typed field polish` | 6b (remainder), 6c |
| 3 | `refactor: StoreSessionInDatabase bool + WithIDGenerator` | 6d, 6e |
| 4 | `refactor: ListSessions pushdown + DeleteVerificationsByValue LIKE ESCAPE` | 7 D3, D4 |
| 5 | `fix: bearer default warning + header injection guard + RateLimiter hook` | 8 |
| 6 | `chore: error registry consolidation + logger gating` | 9 |
| 7 | `test: harness t.Fatalf + t.Helper + lint config + WithClock + SecureCookies cache` | 10 |

Verification for the whole batch:
```bash
GOCACHE=$TMPDIR/gocache go -C goauth vet ./...
GOCACHE=$TMPDIR/gocache go -C goauth test ./src/tests/compat ./src/app/services/session ./src/providers/origin -count=1 -timeout 60s
# manual
go -C goauth run ./src/example & # /api/auth/ok 200, sign-up -> Bearer JWT 401 after sign-out
```

Exit criteria: `grep -rn "Extras\[" goauth --include="*.go"` shows only the escape-hatch fallback in `goauth.go`; no `blacklist:` writes remain; `src/tests/compat/golden/*.json` updated if error shape changed.

### 2. Sid -> token index follow-through (S)

- Confirm `sid:token` index (`SidPrefix`) is plugin-owned (`src/plugins/access-token/services/serv.session.go`) and not leaking into `src/app/services/session` core. Done on `feat/sid-token-index`; verify with `grep -rn "sid:" goauth --include="*.go"` — only access-token plugin should write it.
- Keep compat read for `blacklist:` / `revoked:session:` until TTL expires (see `01` §3). Remove legacy prefix after one minor version and update `revocation_store.go` + `funcs.go`.
- Add `IsTokenLike` guard before `Header.Set("Cookie", ...+tok)` injection in `access_token.plugin.go:358` (belongs to this queue item or #1/5).

### 3. Official `better-auth/client` script against goauth (M)

The last "done when" of step 6. Steps:
- Add or update `03-spec/06-compat-testing.md` with the script (sign up → sign in → get-session → sign out) and expected status codes/cookies/headers.
- Run it against `src/tests/compat/server.go` or `src/example/main.go` (matrix: sqlite + postgres, with/without secondary storage).
- Wire into CI or document manual invocation. This gates moving step 6 to fully ✅.

### 4. Config sections — `User` / `Account` / `Verification` / `RateLimit` (M)

Per `03-spec/04-config.md` and `02-steps.md` step 1 "Open" items. Introduce `GoAuth` sub-structs, map old fields in `SetDefaults` with deprecation logs, add table tests for defaults and old→new mapping, keep e2e tests green. Do this before DTO convergence so config drives model options.

### 5. Session additionalFields & DTO convergence (M)

- Generic `session.additionalFields` (today only `GoAuth.Session.UpdatableFields` allowlist of device fields). Implement as real columns via migrator (driven by `Session.AdditionalFields` declaration), wire `UpdateSession` to it, add contract tests.
- Decide `models.Session.Token json:"-"` exposure for DTO convergence (hashed vs raw; likely keep split with `dtos.BetterAuthSession` / `SessionResponse` until token-hashing lands).

### 6. Org parity — teams, dynamic access control, `organizationRole` (L)

From `02-steps.md` breaking checklist: add `team`, `teamMember`, `session.activeTeamId`, `invitation.teamId`; replace `OrgPermission` with `organizationRole`; implement dynamic `RequireOrgMember` with permission-based checks. Spec in `03-spec/05-plugins.md` + `06-explain/*.md`. Create `04-plan/NN-org-teams.md` sub-plan before coding.

### 7. Admin parity — fold `user.active`/`accountStatus` into `banned/banReason/banExpires` (M)

Breaking checklist item; keep `AfterDelete` hook for audit trails. Add migration, update admin plugin hook `BeforeSessionCreate` that already returns `ErrBannedUser`, and port the TypeScript ban tests.

### 8. IDs — better-auth 32-char alphanumeric default, ULID opt-in (S)

Replace global `models.SetIDGenerator` default with better-auth's 32-char `[a-zA-Z0-9]` generator; keep ULID as option via `Advanced.GenerateID` / `Manager.WithIDGenerator`. Update `02-steps.md` checklist and add a migration note (ID format is not backfilled; only new rows change).

### 9. Versioned SQL migrations (M)

Move from `PrepareLegacyColumns` + `core_migration.GORMAdminMigrator` to versioned migrations (Atlas or goose) from a `better-auth` CLI baseline. Delete `PrepareLegacyColumns` once the baseline is established. MySQL needs `DefaultStringSize: 191` or sized indexed columns. Add fixture tests on SQLite and Postgres.

### 10. Cross-implementation DB tests (M)

Run the TypeScript server (`better-auth-schema/`) and goauth on one Postgres database: sign up on one, sign in on the other, cookies, `get-session`, `list-sessions`, org endpoints. This is the final "compatible" gate (priority 3 of `_docs/README.md`). Add `03-spec/06-compat-testing.md` section and CI job.

### 11. Cookie cache, hashed tokens, rate limiting, phone plugin (L, later)

Phases 7, 8 (remainder), 9–11 of `01-roadmap-v1-superseded.md` / `03-spec/05-plugins.md`, ordered easy→hard: `username` → `anonymous` → `last-login-method` → `multi-session` → `one-time-token` → `email-otp` → `magic-link` → `phone-number` → … → `passkey`/`oauth-provider`. Pick per product need; each gets its own `04-plan/NN-*.md` sub-plan. Do not start until tasks 1–10 are green or explicitly deferred with a reason in `04-plan/02-steps.md`.

## Also keep in view

- **`05-notes/01-open-questions.md`:** "0-row update → not modified error", `RawBodyMetaKey`/`Transform`/`Document Operation`, optional full name. Answer or spec each before it blocks a feature.
- **`phase1/06-explain`:** session services + auth flows explainers — update when `manager_update.go` / `SessionPatch` / sid index semantics change.
- **`03-spec/07-phone-and-no-email-users.md`:** phone plugin spec — next plugin after bearer/jwt unless product priority says otherwise.

## How to work this queue

- Keep `04-plan/02-steps.md` as the canonical status; update it after every step. These `phase2/*.md` files are a snapshot dated 2026-10-16 — refresh or delete them when the branch merges.
- One branch per task (or per small group of tasks 1.x), each leaving `go build ./... && go vet ./... && go test ./...` green and legacy e2e tests passing unless the commit explicitly changes a contract (then update goldens in the same commit).
- File new work as `04-plan/NN-topic.md`, rename to `NN-done-topic.md` when finished, per `_docs/README.md`.
