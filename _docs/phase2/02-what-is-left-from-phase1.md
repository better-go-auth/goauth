# Phase 2 — What is left from Phase 1

Source of truth: `_docs/phase1/04-plan/02-steps.md` (active plan) plus `01-roadmap-v1-superseded.md` for later phases. This note reconciles that plan against the current code on `feat/improvements-1-10` (2 commits past `feat/sid-token-index`).

## Already done (verify before closing)

| Step | Claim in `02-steps.md` | Reality check |
|---|---|---|
| **0** providers | `authcrypto`, `cookies.Manager`, `idgen` with vectors | Done. |
| **1** config reshape | `GoAuth.Mode`, `GoAuth.Session`, `EmailVerification.GoAuth`, `Advanced.GoAuth.OverrideHumaErrors`, derived JWT keys, `typ` claim | **Partial** — `User`, `Account`, `Verification`, `RateLimit` sections not yet introduced; old-field mapping in `SetDefaults` missing (breaking instead of deprecated). |
| **2** models/migration | better-auth fields first, `TablePrefix/TableNames`, constraints, FK `impersonatedBy`, `activeOrganizationId` | Mostly done; open: camelCase columns (step 10), `team`/`teamMember`/`organizationRole` tables, sized MySQL indexes. |
| **3** repositories | struct conditions, `Col/OrderBy/ILike/IEq`, contract suite | Done. |
| **4** shared foundations | `common/errors` `AuthError`+registry, `session` Manager, `humaadapter` Resolver, `dtos.SessionWithUser` | Done; `models.Session.Token json:"-"` + wire DTO split kept intentionally. Merging DTOs deferred to `02-what-is-left` below. |
| **5** auth services | `src/app/services/auth` (`IAuthService`/`ISessionService`/`IUserService`) | ✅ except noted gaps: generic `session.additionalFields`, OAuth/social linking, `customSyntheticUser`, cookie cache, JWT plugin. |
| **6** huma adapter | `src/app/adapters/huma/RegisterRoutes` (compat), origin/CSRF, golden tests | ✅ except official `better-auth/client` script (last "done when" of step 6) not yet run in CI. |
| **7** legacy transport on shared core | legacy routes rebuilt on `session.Manager`, refresh-token == session token, `sid` JWT, blacklist key | ✅; `src/tests/compat/legacy_transport_test.go` passes. Follow-up: remove `blacklist:` dual-read after TTL expires (covered in phase2/01). |
| **8** admin plugin | `GET /admin/list-users`, `set-role`, `get-user`, `update-user`, `has-permission`, impersonation, ban hook | Reported **COMPLETED** in `02-steps.md`; verify with `go test ./src/plugins/admin/...` and `TestAdminE2E_FullFlow`. Breaking checklist item "fold `user.active`/`accountStatus` into `banned/banReason/banExpires`" still unchecked — see below. |
| **9** organization plugin | schema, roles `owner/admin/member`, user vs org-scoped routes, `dtos.SessionWithUser` | Reported **COMPLETED**; verify with `go test ./src/plugins/org/...` and `TestOfficialBetterAuthClient`. Breaking checklist items "Replace `OrgPermission` with `organizationRole`" and "teams (`team`, `teamMember`, `session.activeTeamId`, `invitation.teamId`), dynamic access control, permission-based `RequireOrgMember`" still unchecked. |
| **10** camelCase columns | `NamingBetterAuth` GORM namer | Optional, **not started**. Prerequisites are done (struct conditions, Go field names as update keys). Remaining: name indexes explicitly (`uniqueIndex:user_email_key`), GORM namer implementation. |
| **11** later | JWT/JWKS, bearer, social OAuth, rate limiting, email OTP, 2FA | **JWT + bearer landed** as `src/plugins/jwt` and `src/plugins/bearer` on `feat/sid-token-index` + improvements; social OAuth / phone / rate limiting still later. |

## Gaps that are still real work

### From `02-steps.md` "Open" and "Not done"

1. **Step 1 — finish config sections** (`User`, `Account`, `Verification`, `RateLimit` per `03-spec/04-config.md`). Add mapping of old fields in `SetDefaults` with deprecation logs, and table tests for defaults + old→new mapping.
2. **Step 5 — narrow the auth-service gaps:**
   - generic `session.additionalFields` (today only allowlisted device fields via `GoAuth.Session.UpdatableFields`);
   - OAuth / social linking;
   - `customSyntheticUser`;
   - cookie cache, JWT plugin (JWT now exists as plugin, but cookie cache `compact`/`jwt`/`jwe` strategies still missing);
   - `user.additionalFields` storage as real columns via migrator.
3. **Step 6 — official client script:** run the `better-auth/client` script against goauth (sign up → sign in → get-session → sign out) as the last acceptance gate. Wire it in CI or document manual steps in `03-spec/06-compat-testing.md`.
4. **Step 5/6 DTO convergence:** `models.Session.Token json:"-"` split from `dtos.SessionResponse`/`BetterAuthSession` was kept deliberately; merging them is part of step 6 but needs `Session.Token` exposure decision (hashed vs raw) — track explicitly.

### From `02-steps.md` breaking clean-up checklist (unchecked items)

> Copy of the checklist with current status. Check an item only when its migration + tests are done and `PrepareLegacyColumns` no longer references it.

- [ ] Replace the `OrgPermission` table with `organizationRole` (step 9).
- [ ] camelCase columns (step 10) — name indexes explicitly (`uniqueIndex:user_email_key`).
- [ ] Drop user soft delete (`deletedAt`); better-auth deletes and cascades. Use an `AfterDelete` hook for audit trails.
- [ ] Fold `user.active` / `accountStatus` into the admin plugin's `banned` / `banReason` / `banExpires`.
- [ ] Organization `status` / `createdBy` (approval workflow) as opt-in additional fields.
- [ ] Sessions and tokens: JWT access/refresh as an opt-in transport on the session (step 7) — JWT is a plugin now, but legacy `/login`/`/refresh` still exist; decide when to move them into the JWT transport and deprecate legacy.
- [ ] IDs: better-auth's 32-char random alphanumeric by default, ULID as an option (still ULID today via `models.SetIDGenerator` global).
- [ ] Only better-auth routes and bodies; legacy `/login`, `/refresh` move into the JWT transport (step 7).
- [ ] Org parity: teams (`team`, `teamMember`, `session.activeTeamId`, `invitation.teamId`), dynamic access control, permission-based `RequireOrgMember` (step 9).
- [ ] Versioned SQL migrations (Atlas or goose) from a better-auth CLI baseline; delete `PrepareLegacyColumns`. MySQL needs `DefaultStringSize: 191` or sized indexed columns.
- [ ] Cross-implementation tests: TypeScript server (`better-auth-schema/`) and goauth on one Postgres database (sign up on one, sign in on the other, cookies, `get-session`, `list-sessions`, org endpoints).

Each of these should become its own entry in `04-plan/02-steps.md` (or a `04-plan/NN-*.md` sub-plan renamed to `NN-done-*` when finished) rather than being tracked only here.

### From `05-notes/01-open-questions.md`

- Repository updates that change 0 rows should return a "not modified" error — spec the error code and add contract tests.
- `common/types` `RawBodyMetaKey`, `Transform`, `Document Operation` — document or delete.
- Make the full name optional — decide and spec.
- `Advanced.GenerateID` vs global `SetIDGenerator` — converge on `Manager` option `WithIDGenerator` (see `phase2/01-improvements-and-fixes.md` §6e).

## Spec docs that need updating when the above moves

- `03-spec/04-config.md` — when `User`/`Account`/`Verification`/`RateLimit` sections land.
- `03-spec/03-schema.md` — when `team`/`teamMember`/`organizationRole` or camelCase columns land.
- `03-spec/05-plugins.md` — when org teams / admin re-align / JWT+bearer promotion lands.
- `03-spec/06-compat-testing.md` — when the official client script and cross-DB tests land.
- `04-plan/02-steps.md` — after every step; this file is the canonical status, this phase2 note is just a snapshot.
- `05-notes/01-open-questions.md` — move answered items to "Answered / done" with a link to the doc that answers them.

## How to use this file

- Treat it as a **snapshot** dated 2026-10-16 on `feat/improvements-1-10`. The canonical status remains `04-plan/02-steps.md` — update that file when work lands, and refresh this note only if it drifts.
- When you pick up a gap, create a numbered `04-plan/NN-topic.md` plan for it, implement on a branch, and rename to `NN-done-topic.md` when green.
