# 04 – Steps

Ordered by dependency. Every step must leave `go build ./... && go vet ./... && go test ./...` green and keep
the legacy e2e tests (`src/tests/{auth,profile,session,admin}`, `src/plugins/org/test`) passing unless
the step explicitly changes their contract.

## Step 0 – Extract providers ✅

`src/providers/authcrypto`, `src/providers/cookies` (`cookies.Manager`, `cookies.New`), `src/providers/idgen`.
Test vectors in `src/providers/authcrypto/testdata/better_auth_vectors.json`.

## Step 1 – Config reshape (S) ✅ (partial)

Done: `GoAuth.Mode`, `GoAuth.Session{SingleSession, JWT}`, `EmailVerification.GoAuth{CodeSender, CodeGenerator, CodeExpiresIn}`,
`Advanced.GoAuth.OverrideHumaErrors`; JWT keys derived from `Secret` (must differ); `typ` claim checked by
`ValidateAccessToken` / `ValidateRefreshToken`. Old fields were removed instead of mapped (breaking).
Open: `User`, `Account`, `Verification`, `RateLimit` sections.

- Introduce the sections and `GoAuth` sub-structs from 03-config.md.
- Map the old fields in `SetDefaults` and log deprecations.
- Derive two different JWT keys from `Secret` when the access/refresh secrets are empty
  (`HMAC(secret, "goauth-access")`, `HMAC(secret, "goauth-refresh")`), and add a `typ` claim check.
  This fixes the refresh-token-as-access-token issue.
- **Done when:** table tests cover defaults and old → new mapping, and the existing e2e tests pass unchanged.

## Step 2 – Models and migration (M) ✅ (except columns and org opt-in tables)

Done: better-auth fields first, extras last; tables `user`, `session`, `account`, `verification`, `organization`,
`member`, `invitation` (`GoAuth.TablePrefix` / `GoAuth.TableNames` via `models.SetTableNames`); `createdAt`/`updatedAt`
NOT NULL; `user.email` NOT NULL + lowercased; `user.emailVerified` NOT NULL; `user.image` nullable; FKs
`session.impersonatedBy → user`, `session.activeOrganizationId → organization` (org plugin); `invitation.expiresAt` NOT NULL;
`session_id` / `hashed_token` / `role` removed. Open: camelCase columns (step 10), `team` / `teamMember` / `organizationRole`.

- Rewrite `src/models` and `src/plugins/org/models` per 02-schema.md: better-auth fields first, goauth
  extras at the bottom, camelCase JSON, `TableName()` returning better-auth names (overridable via
  `User.ModelName` etc.).
- Session: `Token` not null; drop `SessionId`, `HashedToken`, `Role`; `HashTokens` option in the repository.
- Data migration (02-schema.md § Data migration), idempotent, with dry-run.
- **Done when:**
  - A fresh database matches better-auth's schema in snake_case. Check by running the TypeScript server
    (`better-auth-schema`) with `fields` mappings to snake_case and `npx @better-auth/cli migrate`; it must report no changes.
  - A database dump from the current release migrates cleanly (fixture test on SQLite and Postgres).

## Step 3 – Repositories (M) ✅

Done: all GORM repos use struct conditions with named fields (`Where(&models.Session{Token: t}, "Token")`, so an
empty value matches nothing), `gormutil.Col/OrderBy/ILike/IEq` for non-equality conditions, and Go field names as
`Updates` map keys. Contracts renamed (`FindUserByID`, `FindSession(token)`, `DeleteSession(token)`, `DeleteUserSessions`,
`ListSessions`, `FindAccounts`, `FindAccountByProviderID`, `UpsertVerificationValue`, `FindVerificationValue`, ...).
`src/app/repository/repotest` is the contract suite; it runs against `gormauth` (SQLite) and `memory` (in-memory).

- Contracts in `repo_interfaces` named after better-auth's internal adapter operations:
  `CreateUser, FindUserByID, FindUserByEmail, UpdateUser, DeleteUser, ListUsers`,
  `CreateSession, FindSession(token), UpdateSession, DeleteSession(token), DeleteUserSessions, ListUserSessions, DeleteExpiredSessions`,
  `CreateAccount, FindAccounts(userID), FindAccount(provider, accountID), UpdateAccount, DeleteAccount`,
  `CreateVerification, FindVerification(identifier), DeleteVerification, DeleteExpiredVerifications`,
  plus `ITxManager`.
- `gormauth` implements them using **struct fields** in queries (`Where(&models.Session{Token: t})`), never
  raw column strings. This is what makes step 10 possible.
- Repositories are injectable through `GoAuthOptions.Repositories`; `Conn` is only a shortcut for GORM.
- Keep the old methods as thin wrappers until step 7 removes their last callers.
- **Done when:** a repository contract test suite runs against `gormauth` (SQLite) and an in-memory fake.

## Step 4 – Shared foundations (S)

Done: `compat/errors.go` + `apierror.go` merged into `src/common/errors` (`AuthError` + registry `Err/Register/Lookup/Codes`).

- `src/sessions` → `src/app/services/session` (manager) and `src/app/adapters/huma` (middlewares).
- `compat/errors.go` + `apierror.go` → `src/common/errors`; merge with `AuthError` into one type.
- Delete `compat/dto.go`: the session manager returns `models.Session` / `models.User`, which now marshal correctly.
- Fold `src/providers/hasher` into `authcrypto`.
- Delete the `compat/` package.

## Step 5 – Auth services (L)

`src/app/services/auth`, framework-agnostic, mirroring better-auth's behaviour endpoint by endpoint:

| Service area | better-auth endpoints covered |
|---|---|
| sign-up / sign-in / sign-out | `sign-up/email`, `sign-in/email`, `sign-out` |
| sessions | `get-session`, `list-sessions`, `revoke-session(s)`, `revoke-other-sessions`, `update-session` |
| user | `update-user`, `change-email`, `delete-user` (+ callback) |
| password | `change-password`, `verify-password`, `request-password-reset`, `reset-password(/:token)` |
| email verification | `send-verification-email`, `verify-email` |
| accounts | `list-accounts`, `unlink-account` (social linking later) |

- Inputs and outputs are plain Go structs.
- Errors are codes from the catalogue.
- Sessions are created by the session service.
- **Done when:** a unit test per behaviour, ported from better-auth's `*.test.ts` cases.

## Step 6 – Huma adapter (M)

- `src/app/adapters/huma` registers the better-auth endpoints over the services (moves `src/app/core/ba` here).
- It also provides the session middlewares, cookies and the raw-body marker.
- Plugins (admin, org) use the same middlewares to read the session.
- **Done when:** golden tests in `src/tests/compat` pass for every endpoint, and the official `better-auth/client`
  script signs up, signs in, reads the session and signs out against goauth.

## Step 7 – Legacy transport on the shared core (M)

- `src/app/services/token`: JWT access token `{sub, sid=session.id, role, activeOrganizationId, activeOrganizationRole, typ:"access"}`.
  The refresh token is the session token.
- Legacy services in `src/app/core/*` call `services/auth` + `services/session` + `services/token`. Routes and
  request/response shapes stay the same, except JSON key casing; see Risks.
- `AuthMiddleware.Authenticate` accepts a legacy access JWT **or** a cookie/bearer session token and puts one
  session type in the context.
- Revocation = delete the session row. Drop the blacklist keys and the `blacklisted`/`revoked_at` columns.
- **Done when:** the legacy e2e tests pass on the new core, and a cookie session and a JWT session for the same user
  both appear in `list-sessions`.

## Step 8 – Admin plugin (M)

- Endpoints and bodies per better-auth: `GET /admin/list-users` with query params, `set-role`,
  `get-user`, `update-user`, `has-permission`.
- Impersonation creates a normal session with `impersonatedBy` and an `admin_session` cookie.
- Ban check moves into a sign-in hook.
- **Done when:** admin tests ported from better-auth pass, and old paths stay as aliases in `ModeLegacy`.

## Step 9 – Organization plugin (L)

- Schema per 02-schema.md, roles `owner/admin/member`, active org on the session.
- User-scoped routes (`create`, `list`, `set-active`, invitations) only require a session; org-scoped routes take
  `organizationId` and check membership in the database. This fixes the "no active org" dead end.
- Optional later: teams, dynamic roles (`organization_role`).
- **Done when:** a real flow passes: sign up, create org, set active, invite, accept as a second user.

## Step 10 – camelCase columns (optional, M)

- `Schema.Naming = NamingBetterAuth` via a GORM `schema.Namer`, for sharing one database with a TypeScript better-auth server
  without `fields` mappings.
- Only possible because step 3 removed raw column strings.

## Step 11 – Later

JWT/JWKS plugin, bearer plugin, social OAuth, rate limiting, origin/CSRF checks, email OTP, two-factor. See `../05-plugins.md`.

## Risks

| Risk | Mitigation |
|---|---|
| Legacy JSON keys change (`created_at` → `createdAt`, `org_id` → `activeOrganizationId`) | Release note. Optional legacy presenter that maps old keys for one version. |
| Existing sessions are invalidated by step 2 | Announce a forced re-login, or keep the old columns until step 7 and migrate then. |
| Table renames break host apps that query `auth_users` directly | `User.ModelName` etc. can keep the old names. |
| Step 2 + 7 change many files at once | Each step is its own branch and PR. Steps 2 and 7 are the major-version boundary (`/v2` module path). |
