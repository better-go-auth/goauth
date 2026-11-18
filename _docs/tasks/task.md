# tasks 


## keeping access token logic only to the access token plugin
- [x] remove the access token verifier from the core plugin because it doesnt need it, plus it must use the secret by default even if it exist.
it is doing a redundant logic. 

- [x] default middleware is unaware of access token and only works as default cookie / session resolution.
- [x] access token plugin exports its own middleware (Middleware(), AuthMiddleware(), InitMiddleware(), HTTPMiddleware()) for client apps to use manually.

## Route Classification & Refresh Token Protection Plan
- [x] Create comprehensive plan in `_docs/phase5/02-access-token-route-protection-plan.md` for route boundaries and refresh-token-only route protection.
- [x] Strict Secret Separation: Restrict `AccessSecret` exclusively to signing and validating access token JWTs. All cookies (including signed session tokens in cookies) exclusively use core `Secret`.
- [x] Refresh Token Invariant: Reject 3-segment access token JWTs (`strings.Count(token, ".") == 2`) in `FindByRefreshToken`, `ResetToken`, and `Logout` with invalid token error.
- [x] Scoped Middleware & Opt-in Global Registration: Added `AutoRegisterMiddleware` (default `false`) and exported `RequireRefreshToken()` guard middleware for routes strictly requiring a genuine refresh token.
- [x] Comprehensive Test Suite: Added unit tests for secret separation, refresh token JWT rejection, and scoped guard middleware; 100% test pass rate across the entire repository.
- [x] Optional / Pass-Through Authentication Middleware: Implemented `AuthenticateOptional()` (and alias `AuthenticateIfToken()`) on `IAuthMiddleware` and `*AuthMiddleware`. Supports optional pointer option struct `*AuthenticateOptions` with `RequireAuth bool`. If `RequireAuth: true`, requires valid claims, session cookie, or bearer token; otherwise rejects with 401 Unauthorized.
- [x] Struct-Based Database Queries: Converted database queries/updates using `map[string]interface{}` / `map[string]any` to typed structs where possible, while preserving maps specifically for operations that update pointers to null or zero values (such as `UnbanUser`).

## Organization Role Permission Refactoring & Verification
- [x] Refactored `OrganizationRole.Permission` to custom type `type Permission map[string][]string` with serializer tag `gorm:"serializer:json;type:text;not null" bun:"permission,notnull"`.
- [x] Implemented `driver.Valuer` (`Value()`), `sql.Scanner` (`Scan()`), and `json.Unmarshaler` (`UnmarshalJSON()`) supporting both JSON objects and stringified JSON.
- [x] Added `HasAction(resource, action string) bool` with wildcard support and `ParsePermission(v any)` helper.
- [x] Updated repository (`team_repo.go`), services (`serv.team.go`), and DTOs (`dtos/request.go`, `dtos/response.go`) to use `Permission`.
- [x] Added tests verifying serialization, raw DB text, querying, updates, and permission evaluation on both SQLite and PostgreSQL via testcontainers.

## Phase 6: Dynamic Role & Permission Caching Strategy
- [x] Formulated detailed Phase 6 architectural plan in `_docs/phase6/01-dynamic-role-caching-strategy.md` analyzing three approaches: (1) caching permissions inside the access token JWT, (2) caching permissions inside the user session, and (3) caching organization roles on secondary storage with an L1 memory read tier. Recommended Option 3 for optimal wire size, $O(1)$ invalidation, and sub-microsecond evaluation.
- [x] Implemented two-tier dynamic role caching (L1 `sync.Map` + L2 `SecondaryStorage`) in `OrgService` with $O(1)$ invalidation on role creation, update, deletion, and organization removal.
- [x] Replaced `[]string` on `OrganizationRole.Ops` with custom `Operations` type implementing `driver.Valuer` (`Value()`), `sql.Scanner` (`Scan()`), `json.Unmarshaler` (`UnmarshalJSON()`), `HasOp(operationID string) bool`, and `ParseOperations(v any)` for multi-ORM compatibility (GORM, Bun, std SQL).
- [x] Added `AuthMethod` configuration (`permission`, `ops`, `both`) to `DynamicAccessControlConfig` with configurable `CacheTTL` and `L1CacheTTL`.
- [x] Extended `ITeamService` / `OrgService` with strongly typed `CreateRole`, `CreateRoleWithOps`, `UpdateRole`, `UpdateRoleWithOps`, `HasOperation`, and `AuthorizeRole` using `models.Permission` and `models.Operations` instead of `any`.
- [x] Exported Huma and standard `net/http` authorization middleware on `OrgPlugin` (`Authorize`, `RequirePermission`, `RequireOperation`, `HTTPAuthorize`, `HTTPRequirePermission`, `HTTPRequireOperation`) resolving active org and role via fast-path claims or DB fallback.
- [x] Added comprehensive tests modularized into clean, focused test files (`permission_test.go`, `permission_db_test.go`, `dynamic_role_caching_test.go`, `middleware_test.go`) verifying `Operations`/`Permission` scanner/valuer, two-tier cache hits/invalidation, operations checks, and middleware enforcement across SQLite, PostgreSQL, and MySQL testcontainers.
- [x] Enforced strict repository validation in `org.New()` (verifying `ITeamRepo` and `ITeamMemberRepo` when teams are enabled, and `IOrganizationRoleRepo` when dynamic roles are enabled), and refactored `svc.SetRepositories(p.orgRepos)` to conditionally bind repositories according to active feature configs.

## Multi-Database Support & MySQL Testcontainer Refactoring
- [x] Implemented MySQL testcontainer (`mysql:8.0`) and multi-database test helpers in `src/tests/helpers/db_testcontainers.go`.
- [x] Added `SetupTestDB(t, dbType)`, `SetupTestEnvWithDB(t, dbType)`, `RunMigrations(t, db)`, and `RunForEachDB(t, fn)` parameterized test runner for SQLite, PostgreSQL, and MySQL.
- [x] Fixed MySQL InnoDB key length specifications (Error 1170) on `Session` (`impersonated_by`, `active_organization_id`, `active_team_id`), `Account` (`account_id`, `provider_id`, `user_id`), `Verification` (`identifier`), and `OrganizationRole` (`organization_id`, `role`).
- [x] Refactored `permission_test.go` and `team_test.go` to run seamlessly and verified 100% pass across SQLite, PostgreSQL, and MySQL.

## Phase 7: Multi-ORM & Database Abstraction Architecture Plan
- [x] Evaluated major Go ORMs and SQL data access libraries (`database/sql`, `sqlx`, `sqlc`, `bun`, `ent`, `gorm`, `pgx`, `bob`) across paradigm, type-safety, performance, and compatibility in `_docs/phase7/01-go-orm-ecosystem-evaluation.md`.
- [x] Formulated architectural decoupling plan in `_docs/phase7/02-architecture-decoupling-strategy.md` addressing model neutralization (`*time.Time` soft-delete), generic context-based `ITransactionManager`, canonical error normalizer, and dual-track migrations.
- [x] Developed comprehensive, step-by-step implementation blueprints in `_docs/phase7/03-implementation-plans-by-orm.md` for `sqlc`, standard `database/sql`, `sqlx`, `Bun`, `Ent`, and `GORM`.
- [x] Designed universal schema DDL and contract test verification framework across SQLite, PostgreSQL, and MySQL in `_docs/phase7/04-schema-migrations-and-testing-strategy.md`.
- [x] Created index and navigation guide in `_docs/phase7/README.md`.

## Phase 7: Multi-ORM & Database Abstraction Implementation
- [x] **Step 1: Domain Model Neutralization**:
  - Replaced `gorm.DeletedAt` with pure Go `*time.Time` (`gorm:"index" bun:"deleted_at,soft_delete" json:"deletedAt,omitempty"`) across all domain models (`User`, `SDBase`).
  - Purged all `gorm.io/gorm` and `gorm.io/gorm/schema` imports from core domain models (`src/models/common.go`, `auth.user.go`, `auth.session.go`, `auth.account.go`, `auth.verification.go`, `tables.go`).
  - Relocated GORM-specific `NamingStrategy` to `src/common/gormutil/naming.go` with multi-tenant prefix/override support and struct name resolution, verified by dedicated unit tests.
  - Replaced model lifecycle hooks (`BeforeSave(*gorm.DB)`, `BeforeCreate(*gorm.DB)`) with pure domain helpers (`EnsureID()`, `PrepareSave()`, `EnsureUTC()`).
  - Created `src/common/gormutil/callbacks.go` registering GORM lifecycle callbacks (`goauth:lifecycle`) on `db.Callback().Create().Before("gorm:create")` to preserve automatic ID initialization and UTC timestamp normalization for raw GORM operations without domain model coupling.
  - Updated GORM repositories (`user_repo.go`, `session_repo.go`, `verification_repo.go`, `auth_repos.go`, `admin_repo.go`) and `memory.go` to handle soft-delete filters (`deleted_at IS NULL`) and lifecycle helpers.
  - Verified 100% pass across all unit tests and integration tests across SQLite, PostgreSQL, and MySQL testcontainers.

## Phase 8: Custom Columns & Additional Fields Architecture Plan
- [x] Evaluated Go architectural patterns (Dynamic SQL columns, JSONB metadata document, Go generics, and struct embedding) in `_docs/phase8/01-custom-fields-design-patterns.md`, establishing flattened JSON wire format for 100% Better-Auth client compatibility.
- [x] Formulated configuration schema, security controls (mass-assignment and privilege escalation protection via `Input: false`), type coercion, and OpenAPI 3.1 schema enhancement in `_docs/phase8/02-configuration-and-validation-spec.md`.
- [x] Designed multi-ORM storage and querying strategies across GORM, Bun, standard `database/sql`, `sqlx`, `sqlc`, and Ent in `_docs/phase8/03-multi-orm-storage-strategies.md`.
- [x] Created dynamic DDL schema evolution and automated idempotent `ALTER TABLE` migration architecture across SQLite, PostgreSQL, and MySQL in `_docs/phase8/04-dynamic-migrations-and-ddl.md`.
- [x] Authored comprehensive physical columns migration engine architecture (schema introspection, DDL generators, constraint handling on non-empty tables) in `_docs/phase8/05-physical-columns-migration-engine.md`.
- [x] Authored in-depth physical columns repository architecture (Create, Query/Scan, Update, Filter across GORM, Bun, stdsql, sqlc, and Ent) in `_docs/phase8/06-physical-columns-repository-architecture.md`.
- [x] Created file-by-file blueprint of exact additions and modifications across models, DTOs, migrations, repos, validation, and Huma HTTP routes in `_docs/phase8/07-physical-columns-code-changes-guide.md`.
- [x] Created index and navigation guide in `_docs/phase8/README.md`.

## Organization OrgType Support & Session Sync
- [x] **Add `OrgType` to Organization Model and Session Synchronization**:
  - Added `OrgType *string` to [`Organization`](src/plugins/org/models/organization.go) model (`json:"orgType,omitempty" gorm:"size:255" bun:"org_type"`).
  - Added `OrgType *string` to organization request & response DTOs: [`CreateOrgInput`, `UpdateOrgData`, `UpdateOrgInput`](src/plugins/org/dtos/request.go) and [`OrgResponse`](src/plugins/org/dtos/response.go).
  - Added `ActiveOrganizationType *string` to [`Session`](src/models/auth.session.go) (`json:"activeOrganizationType,omitempty" gorm:"size:255" bun:"active_organization_type"`).
  - Added `ActiveOrganizationType *string` to [`SessionData`](src/models/dtos/better_auth.go) and [`UpdateSessionInput`](src/models/dtos/request_dto.go) aligning with `ActiveOrganizationID` and `ActiveOrganizationRole`.
  - Updated session manager, repository layers (`gormauth`, `memory`), and session config patches (`SessionPatch.ToMap()`) to support `ActiveOrganizationType`.
  - Updated [`OrgService.SetActiveOrganization`](src/plugins/org/services/serv.org.go) to fetch target organization's `OrgType` and persist it to `session.ActiveOrganizationType`, clearing it when `orgID == nil`.
  - Updated [`OrgService.CreateOrganization`](src/plugins/org/services/serv.org.go), `AdminCreateOrganization`, and `UpdateOrganization` to persist and update `OrgType`.
  - Updated JWT and claims layers ([`token.CustomClaims`](src/providers/token/token.go), [`jwtClaims`](src/providers/token/jwt-token/jwt_managers.go), [`from-claims.go`](src/providers/authenticator/from-claims.go), [`session_claims.go`](src/app/adapters/huma/session_claims.go), and [`access-token`](src/plugins/access-token/access-token-middleware.go) Layer 1 and Layer 2) to sync and diff `ActiveOrgType`.
  - Added automated test in [`org_type_test.go`](src/plugins/org/test/org_type_test.go) verifying org creation with `OrgType`, active org switching, session type synchronization, and session clearing.

## Phase 9: Audit fixes and new better-auth plugins (2026-11-17)
- [x] Plugin routes now receive the HTTP request in ctx (session IP/user agent, callbacks get the request) via a global request-context middleware.
- [x] Core fires `BeforeUserCreate` (sign-up) and `UserDeleted` (delete-user) hooks; email change checks for a taken email before creating a session.
- [x] Email-OTP matches better-auth storage (`<type>-otp-<email>`, `change-email-otp-<old>-<new>`, symmetricEncrypt for "encrypted" with legacy AES-GCM read fallback), `{success:true}` change-email responses, silent success for taken emails, `Invalid OTP` message, 400 USER_NOT_FOUND on check, OTP sign-up without credential account.
- [x] Shared infra: `pluginkit` (routes, origin/CSRF, session access levels, cookies, sessions, user hooks), `ratelimit` provider (better-auth fixed window, 429 + X-Retry-After), sign-in interceptor hook (`OnAfterSignIn`), user `phoneNumber`/`phoneNumberVerified`/`twoFactorEnabled`, `FindUserByPhoneNumber` repo method.
- [x] Two-factor plugin (TOTP, OTP, backup codes, trust device) + official client test.
- [x] Magic-link plugin + official client test.
- [x] Phone-number plugin + official client test.
- [x] Passkey (WebAuthn) plugin (go-webauthn) + official `@better-auth/passkey` client test (`src/tests/compat/client-passkey`, run `npm install --legacy-peer-deps` there).
- [x] Social / OAuth2 plugin (google, github, discord, microsoft, apple, facebook, gitlab, generic OIDC) + official client test.

## Phase 9.1: Robustness fixes (`_docs/phases/phase9/01-robustness-and-parity-improvements.md` §1)
- [x] 1.1 Admin remove-user releases the unique phone number (same tombstone as core delete-user); test in `src/tests/admin/admin_test.go`.
- [x] 1.2 Expired verifications are purged on every verification read like better-auth (`verifycleanup.Wrap`, opt out with `Verification.DisableCleanup`); `(*GoAuth).StartCleanup(ctx, interval)` deletes expired sessions and verifications on a ticker.
- [x] 1.3 Atomic OTP attempt counters: `UpdateVerificationValue` (compare-and-swap) and `DeleteVerificationIfValue` on `IVerificationRepo` (GORM + memory + contract tests); email-otp, phone-number and two-factor retry on a lost swap, codes and pending 2FA sign-ins are consumed once.
- [x] 1.4 `active-sessions-<userId>` index updated atomically across processes through the optional `sec_storage.AtomicUpdater` (Redis WATCH/MULTI, memory lock), JSON format unchanged; lock-based fallback for other stores.
- [x] 1.5 Origin/CSRF check on by default for every mutating route under BasePath (org, admin, jwt, access-token included); `Security.DisablePluginOriginCheck` opts out, `CheckOriginOnPluginMutations` extends it to the app's own routes.
- [x] 1.6 Dropped the unique `(user_id, provider_id)` account index (migration drops `idx_user_provider`); `FindAccountByUserAndProvider` returns the oldest account; memory repo enforces `(providerId, accountId)` uniqueness.
- [x] 1.7 Missing query parameters already answer `400 VALIDATION_ERROR` (regression test added for magic-link); admin create-user and email-otp sign-up return `500 FAILED_TO_CREATE_USER` like better-auth (core sign-up keeps 422).
- [x] Storage-agnostic plan for dynamic columns (MongoDB, database/sql/Bun/sqlx/pgx, sqlc, Ent, Atlas/goose/golang-migrate) in `_docs/phases/phase9/04-storage-agnostic-schema-and-migrations.md`.

## Phase 9.4: Access control and most-used missing plugins (2026-11-17)
- [x] `access` (createAccessControl): `src/providers/access` (statements, roles, `Authorize` with better-auth's AND/OR semantics and messages, multi-role `"a,b"`, JSON statements).
  - Admin: per-route better-auth permissions (`RoutePermissions`), `WithAccessControl`/`WithRoles`/`WithAdminUserIDs`/`WithAllowImpersonatingAdmins`, real `/admin/has-permission`, impersonating admins blocked (`YOU_CANNOT_IMPERSONATE_ADMINS`); without custom roles every `AdminRoles` entry keeps full admin access.
  - Org: better-auth mode (ac/roles configured or `BetterAuthPermissions`) vs legacy mode (today's rules, DB roles now merged, multi-role); operation-ID access (`Ops`, `HasOperation`, `AuthMethod`, `OrgPermissionsMap`, `"*"`) unchanged; new routes `/organization/has-permission`, `create-role`, `delete-role`, `list-roles`, `get-role`, `update-role`; fixed `RequireOrgMember` passing the role name as an action.
- [x] Username plugin (`/sign-in/username`, `/is-username-available`, `username`/`displayUsername` validation on sign-up and update-user); user `username` is now nullable + unique (migration turns `''` into NULL).
- [x] Anonymous plugin (`/sign-in/anonymous`, `/delete-anonymous-user`, `isAnonymous`, account linking with `onLinkAccount`).
- [x] Multi-session plugin (`/multi-session/list-device-sessions`, `set-active`, `revoke`, `<session_token>_multi-<token>` cookies, sign-out revokes all).
- [x] One-time-token plugin (`/one-time-token/generate`, `/verify`, plain/hashed/custom storage, single use, `set-ott` header).
- [x] Generic-OAuth plugin (`/sign-in/oauth2`, `/oauth2/callback/:providerId`, `/oauth2/link`, OIDC discovery, 9 presets), reusing the social plugin's OAuth machinery.
- [x] Core extension points: `OnUserInput` (sign-up/update-user body fields), `OnNewSession` (core `NewSessionHooks` middleware), `pluginkit.UseAfterHook` (response after-hooks); multi-session and one-time-token are initialized before other domain plugins so their after-hooks wrap every route.
- [x] Official better-auth client tests for every plugin above (`src/tests/compat/{usernameclient,anonymousclient,multisessionclient,onetimetokenclient,genericoauthclient}`, `TestOfficialBetterAuthClient_Access`).
- [x] Ordered list of the remaining tasks and features (stages 1–7 plus open decisions) in `_docs/tasks/missing-tasks.md`.

## Missing tasks – Stage 1: hygiene and small security fixes (2026-11-18)
- [x] 1.1 `authcrypto.SecureEqual` (constant time) for phone-number OTPs, two-factor backup codes, multi-session cookie tokens, OAuth state (cookie + database strategies) and the Apple ID-token nonce.
- [x] 1.2 The 25 MB `example` binary is untracked and ignored (`/example` in `.gitignore`; it stays in git history).
- [x] 1.3 Repo-wide `gofmt -w`; CI fails on unformatted files.
- [x] 1.4 CI: `go test -race ./...`; Postgres + MySQL matrix job running the repository contract (`TestContract_Postgres` / `TestContract_MySQL`, enabled by `TEST_POSTGRES_URL` / `TEST_MYSQL_URL`) and the official client suites on Postgres; golangci-lint v2 (action v8) for the module's Go version. The matrix found two MySQL bugs, both fixed: the `LIKE ... ESCAPE '\'` in `DeleteVerificationsByValue` was a syntax error (now `ESCAPE '!'`), and username lookups were case-insensitive (binary collation like session tokens).
- [x] Compat suites on `TEST_DATABASE_URL` start each package from an empty Postgres schema (`compattest.NewServer`); before, `genericoauthclient` left the fake provider's user behind and `socialclient` failed its new-user redirect check.
- [x] 1.5 Unknown errors never reach clients: `autherr.Internal` logs the cause with a request ID (reuses an incoming `X-Request-Id`) and answers `500 INTERNAL_SERVER_ERROR` / "Internal Server Error" with `requestId` in the body and `X-Request-Id` header; used by Huma's handler-error path, `types.RespondErr`, the new-session error writer, social sign-in/link and the legacy access-token handlers.
- [x] 1.6 Startup validation: duplicate plugin IDs, missing plugin dependencies (new optional `plugins.DependencyProvider`), duplicate routes (method + path, parameter names ignored) or operation IDs (`types.RegistrationError`, the duplicate is not mounted), and the public dev secrets when `GOAUTH_ENV`/`GO_ENV`/`APP_ENV`/`NODE_ENV` is `production` (a one-time warning otherwise).
- [x] 1.7 One response-hook mechanism: core `humaadapter.ResponseHooks` (registered once, before any plugin route) runs `OnNewSession` hooks and the new `HookRegistry.OnResponse` hooks; `pluginkit.UseAfterHook` registers into it instead of adding its own middleware, so multi-session / one-time-token no longer need early initialization.

## Missing tasks – decisions (2026-11-18)
- [x] User deletion: `User.GoAuth.SoftDelete` (default false = better-auth hard delete). `IUserRepo.DeleteUser` now removes the user with its sessions and accounts, `SoftDeleteUser` keeps the tombstone; one sequence (`src/app/services/userdelete`) for core `/delete-user`, admin `/remove-user` and the anonymous plugin, firing `UserDeleted` before the row delete in hard mode so plugin rows go first. The org hook also removes the user's team memberships and sent invitations. Contract tests for both modes.
- [x] ID format: `Advanced.Database.IDFormat` = `random` (default) | `uuid` | `ulid`, installed process-wide through `idgen.SetGenerator` so plugins use it too; `GenerateID` still overrides it.
- [x] Legacy `/signup`, `/login`, `/refresh` stay in the access-token plugin; core leftovers moved there (`jwt-token` → `src/plugins/access-token/jwttoken`, `RegisterClientInput`, `AuthTokens`, `SessionOpt`, the access/refresh cookie names, and a plugin `LegacySignInResponse` carrying `authTokens`) or removed (`middleware.JWTTokenVerifier`, the JWT step of the core authenticator, unused legacy DTOs).
- [x] Legacy user fields: already folded into `banned`/`banReason`/`banExpires`; removed the unused `enums.AccountStatus` and `models.UserFilter`/`UserQuery`.

## better-auth defaults, goauth behaviour behind GoAuth options (2026-11-18)
- [x] Organization permissions follow better-auth's access control by default; goauth's legacy rules (owner bypass, built-in admin/member rules, `Roles` with `*` wildcards) need `OrgConfig.GoAuth.LegacyPermissions` (or setting the legacy `Roles` map). `BetterAuthPermissions` is deprecated.
- [x] User/session JSON: installed plugins declare their fields (`plugins.SchemaFieldsProvider`: admin, phone-number, two-factor, username, anonymous, organization), and those fields are always present (`false`/`null` when unset; `role` is `"user"` with the admin plugin) like better-auth. Fields of plugins that are not installed are only written when set. The JWT plugin's payload follows the same rule for `role`.
- [x] Update-user: unknown keys are ignored; better-auth's `input: false` fields are skipped when they have a default (`emailVerified`, `banned`, `twoFactorEnabled`, ...) and rejected with `<field> is not allowed to be set` otherwise (`role`, `banReason`, `banExpires`, `phoneNumberVerified`), only while their plugin is installed; a falsy `email` is ignored. The phone-number plugin answers `PHONE_NUMBER_CANNOT_BE_UPDATED`. `User.GoAuth.RejectUnknownUpdateFields` keeps the old `FIELD_NOT_ALLOWED` behaviour.
- [x] Admin: `AdminRoles` entries no longer get full admin permissions on their own (better-auth); `AdminConfig.GoAuth.AdminRolesFullAccess` / `admin.WithAdminRolesFullAccess(true)` restores it.
- [x] Secret: `Secret || $BETTER_AUTH_SECRET || $AUTH_SECRET || DefaultDevSecret` like better-auth; the default is refused in production; `Advanced.GoAuth.RequireSecret` makes a missing secret an error everywhere.
- [x] Internal errors: body is `{code, message}`; `requestId` + `X-Request-Id` only with `Advanced.GoAuth.ErrorRequestID` (the ID is always logged).
- [x] Multi-session: only a validly signed device cookie is required (better-auth); `MultiSessionConfig.GoAuth.StrictDeviceCookie` also requires it to hold the exact token.


## Plugin examples and docs (2026-11-18)

- [x] `src/example/internal/exkit`: shared example wiring (in-memory/file SQLite, goauth on Huma, `Outbox` for sent codes/links, protected `/api/example/me`, graceful `Serve`) and an HTTP test client.
- [x] One runnable, tested package per plugin under `src/example/<plugin>` (`go run` serves on :8080, `go test` runs the flow): access-token, admin, anonymous, bearer, email-otp, generic-oauth, jwt, magic-link, multi-session, one-time-token, org, passkey, phone-number, social, two-factor, username. All pass `go test -race`.
- [x] `src/plugins/<plugin>/example.md` for all 16 plugins (setup, options, endpoints, curl flow, errors, notes); admin and org cover authorization in detail.
- [x] Bugs found while writing the examples (fixed):
  - [x] jwt: `POST /sign-jwt` and `/verify-jwt` are public HTTP routes; anyone can mint a JWKS-valid token for any `sub` (better-auth: server-only). Fixed: routes removed (404); Go API `jwtPlugin.SignJWT` / `VerifyJWT`; `JWTService.SignJWT` takes `*SignJWTOptions`.
  - [x] org: `RequirePermission` trusts the role cached on the session at set-active; update-member-role / remove-member don't refresh it, so demoted or removed members keep access. Fixed: the middleware reads the member row on every request.
  - [x] org: `AuthorizeRole` lets role "owner" pass every check, even resources it has no statement for. Fixed: owner bypass only with legacy permissions (and for goauth-only operation checks).
  - [x] admin: impersonate-user sets no cookies for cookie-authenticated admins. Fixed: `humatypes.MakeResPtr` dropped its cookies; admin routes authenticate with the full session (token, banned flag) before the claims-only one.
  - [x] admin: set-role revokes all of the target's sessions (better-auth doesn't). Fixed: sessions stay; cached sessions get the new user via `RefreshUser`.
  - [x] email-otp: banned user gets `USER_BANNED` instead of `BANNED_USER`. Fixed (also admin impersonate of a banned user, which now ignores expired bans).
  - [x] jwt: nil `DefinePayload` result panics; `KeyPairConfig.Alg/Crv` ignored (always Ed25519). Fixed: nil payload = empty; EdDSA, ES256, ES512, PS256, RS256 (`ModulusLength`) supported, invalid config fails at Init.
  - [x] access-token: no logout route; `/signup` uses gin `binding:` tags (no validation), `lName` required, image stored as "". Fixed: core `POST /sign-out` accepts access/refresh tokens (Bearer or cookie) and expires the plugin cookies; `/signup` validates email + password bounds (core config), `lName`/`avatar` optional, image NULL, email lower-cased, answers 201.
