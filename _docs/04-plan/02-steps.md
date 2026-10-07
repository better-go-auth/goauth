# 02 – Steps (active plan)

Ordered by dependency. Every step must leave `go build ./... && go vet ./... && go test ./...` green and keep
the legacy e2e tests (`src/tests/{auth,profile,session,admin}`, `src/plugins/org/test`) passing unless
the step explicitly changes their contract.

Schema, config and structure referenced here are in [../03-spec](../03-spec). Detail for later phases (security,
hooks, cookie cache, bearer/jwt, OAuth, ecosystem) is in [01-roadmap-v1-superseded.md](01-roadmap-v1-superseded.md).

## Next up

1. Step 7 remainder: merge `dtos.UserResponse` / `SessionData` / `SessionResponse` (legacy core, authenticator,
   admin/org plugins) into the better-auth wire types; legacy JSON keys become camelCase.
2. Steps 8–9: admin and organization plugins on better-auth paths/bodies; org set-active through the shared session.
3. Official `better-auth/client` script against goauth (last "done when" item of step 6).
4. Phone plugin ([../03-spec/07-phone-and-no-email-users.md](../03-spec/07-phone-and-no-email-users.md)).
5. Later: cookie cache, bearer/jwt plugins, opt-in hashed session tokens, rate limiting, camelCase columns.

## Step 0 – Extract providers ✅

`src/providers/authcrypto`, `src/providers/cookies` (`cookies.Manager`, `cookies.New`), `src/providers/idgen`.
Test vectors in `src/providers/authcrypto/testdata/better_auth_vectors.json`.

## Step 1 – Config reshape (S) ✅ (partial)

Done: `GoAuth.Mode`, `GoAuth.Session{SingleSession, JWT}`, `EmailVerification.GoAuth{CodeSender, CodeGenerator, CodeExpiresIn}`,
`Advanced.GoAuth.OverrideHumaErrors`; JWT keys derived from `Secret` (must differ); `typ` claim checked by
`ValidateAccessToken` / `ValidateRefreshToken`. Old fields were removed instead of mapped (breaking).
Open: `User`, `Account`, `Verification`, `RateLimit` sections.

- Introduce the sections and `GoAuth` sub-structs from [04-config.md](../03-spec/04-config.md).
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

- Rewrite `src/models` and `src/plugins/org/models` per [03-schema.md](../03-spec/03-schema.md): better-auth fields first, goauth
  extras at the bottom, camelCase JSON, `TableName()` returning better-auth names (overridable via
  `User.ModelName` etc.).
- Session: `Token` not null; drop `SessionId`, `HashedToken`, `Role`; `HashTokens` option in the repository.
- Data migration (03-schema.md § Data migration), idempotent, with dry-run.
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

## Step 4 – Shared foundations (S) ✅

Done:
- `compat/errors.go` + `apierror.go` merged into `src/common/errors` (`AuthError` + registry `Err/Register/Lookup/Codes`).
- `src/sessions/manager.go` → `src/app/services/session` (package `session`); `middleware.go` → `src/app/adapters/huma`
  (package `humaadapter`, `Resolver`, `WithSession`, `FromContext`).
- `compat/dto.go` → `src/models/dtos/better_auth.go` (`dtos.SessionWithUser`, `BetterAuthSession`, `BetterAuthUser`, `dtos.Time`).
  Kept as wire types instead of marshalling the models directly: `models.Session.Token` is `json:"-"` (legacy rows hold a
  refresh hash), better-auth needs millisecond ISO timestamps, and the user model carries goauth-only fields.
  Merging them with `dtos.SessionResponse` / `SessionData` / `UserResponse` is part of step 6.
- `src/providers/hasher` folded into `authcrypto` (`TokenHash`, `TokenMatches`; verification codes use
  `HashPasswordBcrypt` / `VerifyPassword`). Argon2 refresh-token hashes are no longer accepted.
- `compat/` deleted.

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

Status (✅ except the items below): ported from better-go-auth's `core/services` into package `auth`
(`Service` implements `IAuthService`, `ISessionService`, `IUserService`; built with `auth.New(auth.Deps{...})`),
reusing `session.Manager`, `authcrypto.Passwords` and the renamed repositories. Not wired into `core/auth`;
the huma adapter in `src/app/adapters` comes in step 6. Tests: `service_test.go` (memory repos).
- Follows better-auth rather than better-go-auth where they differ: verification links are better-auth's
  `{email, updateTo, requestType}` JWTs (no DB row), reset tokens are `reset-password:<token>` rows holding the user id,
  credential `accountId` is the user id, change-email has the confirmation / verification / legacy flows.
- Config added: `EmailVerification.{SendVerificationEmail, SendOnSignUp, SendOnSignIn, AutoSignInAfterVerification,
  Before/AfterEmailVerification}`, `EmailAndPassword.OnPasswordReset`, `User.{ChangeEmail, DeleteUser}`,
  `Account.AccountLinking.AllowUnlinkingAll`. `session.Manager.RefreshUser` refreshes cached user snapshots.
- Not done: generic `session.additionalFields` (update-session only writes the allowlisted string fields of the
  session model, `GoAuth.Session.UpdatableFields`, default the device fields), OAuth / social linking,
  `customSyntheticUser`, cookie cache, JWT plugin.
- goauth extension: `EmailAndPassword.GoAuth.SingleResetLink` keeps only the newest reset link valid
  (repo `DeleteVerificationsByValue`).
- Gaps closed after the first pass: atomic `ConsumeVerificationValue` (reset and delete-account tokens),
  `DeleteAccount(id)` for unlinking, delete-user email confirmation + `DeleteUserCallback`, server-only `SetPassword`.
  The ban check moved to the admin plugin's `BeforeSessionCreate` hook (`autherr.ErrBannedUser`).

## Step 6 – Huma adapter (M) ✅ (except the official-client script)

Done: `src/app/core/ba` moved into `src/app/adapters/huma` (`RegisterRoutes`, compat mode only). All core endpoints of
step 5 are mounted over `auth.Service` (`GoAuth.Auth`), with cookies (`Set-Cookie`), redirects (`verify-email`,
`reset-password/:token`, `delete-user/callback`, `?error=CODE`) and better-auth bodies. A request-context middleware puts
the request in ctx for config callbacks and derives the session IP/UA (`Advanced.IPAddress`). Origin/CSRF:
`src/providers/origin` (trusted origins = BaseURL + `TrustedOrigins` + `$BETTER_AUTH_TRUSTED_ORIGINS`, wildcards,
relative paths) and an origin-check middleware (cookie requests need a trusted Origin/Referer; sign-in/up also check
Fetch Metadata), plus callbackURL/redirectTo validation. Unused response DTOs deleted; `AccountResponse` uses `dtos.Time`.
Golden tests: `src/tests/compat/endpoints_test.go` + `golden/*.json`.

- `src/app/adapters/huma` registers the better-auth endpoints over the services (moves `src/app/core/ba` here).
- It also provides the session middlewares, cookies and the raw-body marker.
- Plugins (admin, org) use the same middlewares to read the session.
- **Done when:** golden tests in `src/tests/compat` pass for every endpoint, and the official `better-auth/client`
  script signs up, signs in, reads the session and signs out against goauth.

## Step 7 – Legacy transport on the shared core (M) ✅ (except the DTO merge)

Done: `src/app/core/session` is rebuilt on `session.Manager` (`session.NewService(conf, repos, mgr, store, hooks)`).
Legacy login creates a normal better-auth session; the **refresh token is the session token** (opaque, 32 chars) and
the access token is a JWT with `sid = session.id`, role and active org. `/refresh` slides the session like better-auth
and rotates the token unless `GoAuth.Session.JWT.RotateRefreshToken = false`; `/logout` and revocations delete the
shared row (plus a short `blacklist:<sid>` key so outstanding access JWTs die at once). Re-issuing for an existing
session id (org set-active) updates that session instead of creating one. `AuthMiddleware.Authenticate` accepts an
access JWT, a session token as bearer, or the session cookie (`WithSessions`, `humaadapter.SessionClaims`).
Legacy sessions live for `Session.ExpiresIn` (`JWT.RefreshExpiresIn` only defaults impersonation now); users created by
better-auth sign-up (`Active` nil) may use legacy `/login`. Tests: `src/tests/compat/legacy_transport_test.go`.

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
- (done) Ban check is the admin plugin's `BeforeSessionCreate` hook.
- **Done when:** admin tests ported from better-auth pass, and old paths stay as aliases in `ModeLegacy`.

## Step 9 – Organization plugin (L)

- Schema per [03-schema.md](../03-spec/03-schema.md), roles `owner/admin/member`, active org on the session.
- User-scoped routes (`create`, `list`, `set-active`, invitations) only require a session; org-scoped routes take
  `organizationId` and check membership in the database. This fixes the "no active org" dead end.
- Optional later: teams, dynamic roles (`organization_role`).
- **Done when:** a real flow passes: sign up, create org, set active, invite, accept as a second user.

## Step 10 – camelCase columns (optional, M)

- `Schema.Naming = NamingBetterAuth` via a GORM `schema.Namer`, for sharing one database with a TypeScript better-auth server
  without `fields` mappings.
- Only possible because step 3 removed raw column strings.

## Step 11 – Later

JWT/JWKS plugin, bearer plugin, social OAuth, rate limiting, email OTP, two-factor. See
[../03-spec/05-plugins.md](../03-spec/05-plugins.md) and phases 5–11 of [01-roadmap-v1-superseded.md](01-roadmap-v1-superseded.md).

## Breaking clean-up checklist

Merged from the former `breaking/README.md` (what to do when old databases don't matter).

- [x] Delete `Session.SessionId`, `Blacklisted`, `BlacklistedOn`, `RevokedAt`, `Role`, `HashedToken`; `User.ActiveOrgId`
      ([03-done-remove-session-id.md](03-done-remove-session-id.md)).
- [ ] Replace the `OrgPermission` table with `organizationRole` (step 9).
- [x] better-auth table names, with `GoAuth.TablePrefix` / `GoAuth.TableNames`.
- [ ] camelCase columns (step 10). Prerequisites done: struct conditions, Go field names as update keys, sort allowlists.
      Still to do: name indexes explicitly (`uniqueIndex:user_email_key`).
- [x] Types and constraints: `email` not null/unique/lowercased, `image` nullable, non-pointer timestamps, foreign keys.
- [ ] Drop user soft delete (`deletedAt`); better-auth deletes and cascades. Use an `AfterDelete` hook for audit trails.
- [x] Lowercase roles (`user`, `admin`, comma-separated), member `org_admin` → `admin`.
- [ ] Fold `user.active` / `accountStatus` into the admin plugin's `banned` / `banReason` / `banExpires`.
- [ ] Organization `status` / `createdBy` (approval workflow) as opt-in additional fields.
- [ ] Sessions and tokens: JWT access/refresh as an opt-in transport on the session (step 7).
- [x] Passwords only on the `credential` account, scrypt by default.
- [ ] IDs: better-auth's 32-char random alphanumeric by default, ULID as an option (still ULID today).
- [x] Delete `compat/`, error codes in `src/common/errors`.
- [ ] Models serialize to better-auth's JSON shapes so the separate DTOs go away (step 6).
- [ ] Only better-auth routes and bodies; legacy `/login`, `/refresh` move into the JWT transport (step 7).
- [ ] Org parity: teams (`team`, `teamMember`, `session.activeTeamId`, `invitation.teamId`), dynamic access control,
      permission-based `RequireOrgMember` (step 9).
- [x] Verification uses better-auth's identifiers and values; 6-digit codes stay an extension.
- [ ] Versioned SQL migrations (Atlas or goose) from a better-auth CLI baseline; delete `PrepareLegacyColumns`.
      MySQL needs `DefaultStringSize: 191` or sized indexed columns.
- [ ] Cross-implementation tests: the TypeScript server (`better-auth-schema/`) and goauth on one Postgres database
      (sign up on one, sign in on the other, cookies, `get-session`, `list-sessions`, org endpoints).

## Risks

| Risk | Mitigation |
|---|---|
| Legacy JSON keys change (`created_at` → `createdAt`, `org_id` → `activeOrganizationId`) | Release note. Optional legacy presenter that maps old keys for one version. |
| Existing sessions are invalidated by step 2 | Announce a forced re-login, or keep the old columns until step 7 and migrate then. |
| Table renames break host apps that query `auth_users` directly | `User.ModelName` etc. can keep the old names. |
| Step 2 + 7 change many files at once | Each step is its own branch and PR. Steps 2 and 7 are the major-version boundary (`/v2` module path). |
