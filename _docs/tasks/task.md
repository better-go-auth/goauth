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

## Phase 8: Custom Columns & Additional Fields Architecture Plan
- [x] Evaluated Go architectural patterns (Dynamic SQL columns, JSONB metadata document, Go generics, and struct embedding) in `_docs/phase8/01-custom-fields-design-patterns.md`, establishing flattened JSON wire format for 100% Better-Auth client compatibility.
- [x] Formulated configuration schema, security controls (mass-assignment and privilege escalation protection via `Input: false`), type coercion, and OpenAPI 3.1 schema enhancement in `_docs/phase8/02-configuration-and-validation-spec.md`.
- [x] Designed multi-ORM storage and querying strategies across GORM, Bun, standard `database/sql`, `sqlx`, `sqlc`, and Ent in `_docs/phase8/03-multi-orm-storage-strategies.md`.
- [x] Created dynamic DDL schema evolution and automated idempotent `ALTER TABLE` migration architecture across SQLite, PostgreSQL, and MySQL in `_docs/phase8/04-dynamic-migrations-and-ddl.md`.
- [x] Authored comprehensive physical columns migration engine architecture (schema introspection, DDL generators, constraint handling on non-empty tables) in `_docs/phase8/05-physical-columns-migration-engine.md`.
- [x] Authored in-depth physical columns repository architecture (Create, Query/Scan, Update, Filter across GORM, Bun, stdsql, sqlc, and Ent) in `_docs/phase8/06-physical-columns-repository-architecture.md`.
- [x] Created file-by-file blueprint of exact additions and modifications across models, DTOs, migrations, repos, validation, and Huma HTTP routes in `_docs/phase8/07-physical-columns-code-changes-guide.md`.
- [x] Created index and navigation guide in `_docs/phase8/README.md`.