# 02 – Schema mapping

Rules:
- Table and column names follow better-auth's model and field names in **snake_case**
  (`emailVerified` → `email_verified`). camelCase is step 10.
- Fields better-auth does not have go to the **bottom** of the struct after
  `// ===== goauth fields (not in better-auth) =====`. They must be nullable or have defaults,
  so a better-auth server writing the same table never violates a constraint.
- ID columns widen from `size:26` to `size:36` (or `text`) so ULIDs, UUIDs and 32-char IDs all fit.
- JSON tags use better-auth's camelCase names (`createdAt`, not `created_at`). Legacy responses
  therefore change keys; see the risk note in 04-steps.md.

## Core tables

### `auth_users` → `user`

| better-auth field | column | goauth today | action |
|---|---|---|---|
| id | `id` | ✅ | widen |
| name | `name` | ✅ (added) | keep; first/last name become optional extras |
| email | `email` | ✅ `*string` unique | make `string` not null, lowercase on write |
| emailVerified | `email_verified` | ✅ | — |
| image | `image` | `string` | `*string` |
| createdAt / updatedAt | `created_at` / `updated_at` | ✅ (`*time.Time`) | make non-pointer, JSON camelCase |
| **admin plugin** role | `role` | `"User"`, default `UNVERIFIED_PERSON` | lowercase values, default `user`, comma-separated multi-role allowed |
| admin banned / banReason / banExpires | `banned`, `ban_reason`, `ban_expires` | ✅ | — |
| — | `password` | ✅ already commented out | **drop**; passwords live only on `account` |
| **goauth extras (bottom)** | | | |
| | `first_name`, `last_name` | moved to bottom | optional |
| | `display_name`, `bio`, `date_of_birth`, `gender`, `locale`, `timezone`, `username`, `last_login_ip`, `last_login_at`, `last_seen` | | optional |
| | `active`, `account_status` | | keep; checked by a sign-in hook |
| | `active_org_id` | | deprecated – active org lives on `session` |
| | `deleted_at` | | soft delete stays a goauth feature |

### `auth_sessions` → `session`

| better-auth field | column | goauth today | action |
|---|---|---|---|
| id | `id` | ✅ | widen |
| token | `token` | ✅ (added, unique, nullable) | **not null**; stores the raw token, or `SHA-256(token)` when `Session.GoAuth.HashTokens` is on |
| userId | `user_id` | ✅ | add FK, cascade delete |
| expiresAt | `expires_at` | ✅ | — |
| ipAddress / userAgent | `ip_address` / `user_agent` | ✅ | fill on create |
| createdAt / updatedAt | | ✅ | — |
| admin impersonatedBy | `impersonated_by` | ✅ | widen |
| org activeOrganizationId | `active_organization_id` | `active_org_id` | **rename** |
| org activeTeamId | `active_team_id` | ✅ (added) | — |
| — | `session_id` | legacy JWT `sid` | **drop**; the JWT `sid` claim becomes `session.id` |
| — | `hashed_token` | argon2/SHA-256 of refresh JWT | **drop**; the refresh token *is* the session token (hashed per option) |
| **goauth extras (bottom)** | | | |
| | `org_role_id` → `active_organization_role` | | cached member role for JWT claims |
| | `device_token`, `device_id`, `device_name`, `device_type` | | optional |
| | `last_used_at` | | optional |
| | `blacklisted`, `blacklisted_on`, `revoked_at` | | drop after step 7 (revocation = delete row) |
| | `role` | | drop (read from user) |

Token hashing (`Session.GoAuth.HashTokens`):
- off (default): `token` = raw 32-char token. Byte-compatible with a TypeScript better-auth server on the same DB.
- on: `token` = hex `SHA-256(rawToken)`; lookups hash the presented token first. Protects against a DB leak,
  but a TypeScript server can no longer resolve those sessions.

### `auth_accounts` → `account`

| better-auth field | column | action |
|---|---|---|
| id, accountId, providerId, userId | `id`, `account_id`, `provider_id`, `user_id` | ✅; widen IDs, FK cascade |
| accessToken, refreshToken, idToken | ✅ | encrypt when `Account.EncryptOAuthTokens` (`authcrypto.SymmetricEncrypt`) |
| accessTokenExpiresAt, refreshTokenExpiresAt, scope | ✅ | — |
| password | ✅ | hash format per `EmailAndPassword.Password` (scrypt default) |
| createdAt, updatedAt | ✅ | — |

### `auth_verifications` → `verification`

| better-auth field | column | action |
|---|---|---|
| id, identifier, value, expiresAt, createdAt, updatedAt | ✅ | `identifier`: unique → normal index |
| **goauth extras (bottom)** | `user_id` | nullable |
| | `callback_url` | nullable |

goauth's 6-digit code flows keep their own `identifier` prefixes (e.g. `email-verification:<email>`) and
store the hashed code in `value`, so they don't collide with better-auth's `reset-password:<token>` rows.

## Admin plugin

No tables of its own: `user.role`, `user.banned`, `user.ban_reason`, `user.ban_expires`, `session.impersonated_by`
(all covered above).

## Organization plugin

| better-auth model / field | goauth today | action |
|---|---|---|
| **organization** (`organizations` → `organization`) | | |
| id, name, slug (unique), logo, metadata, createdAt | ✅ | keep; `metadata` stays a JSON string |
| updatedAt | ✅ (Base) | — |
| goauth extras (bottom): `status`, `created_by` | | keep (approval workflow) |
| **member** (`members` → `member`) | | |
| id, organizationId, userId, role (default `member`), createdAt | ✅ | role values `owner` / `admin` / `member` (`org_admin` → `admin`) |
| — | `updated_at` | keep as extra |
| **invitation** (`invitations` → `invitation`) | | |
| id, organizationId, email, role, status (default `pending`), expiresAt, createdAt, inviterId | ✅ | — |
| teamId | ❌ | add (nullable) |
| goauth extras (bottom): `accepted_by_id`, `accepted_at`, `updated_at` | | keep |
| **team** / **team_member** (teams enabled) | ❌ | add when teams are implemented |
| **organization_role** (`dynamicAccessControl`) | `org_permissions` (role/resource/action rows) | new table `organization_role(id, organization_id, role, permission JSON, created_at, updated_at)`; migrate rows grouped by role |

## Data migration for existing databases

One idempotent migration, run by the core migrator before `AutoMigrate`:

1. Rename tables (`auth_users` → `user`, …, `organizations` → `organization`, …) when the old name exists and the new one doesn't.
2. Rename columns (`active_org_id` → `active_organization_id`, `org_role_id` → `active_organization_role`).
3. Backfill `user.name`, copy any remaining `user.password` into a `credential` account, then drop `user.password`.
4. Lowercase `user.role` (`User` → `user`, `Admin` → `admin`, `UNVERIFIED_PERSON` → `user`) and member roles (`org_admin` → `admin`).
5. Sessions: delete legacy rows without a `token`. Every user signs in once more; no live session can be safely converted.
6. Widen ID/FK columns.
7. Drop `session_id`, `hashed_token`, `role` on `session`.

Use GORM's `Migrator().HasTable/RenameTable/HasColumn/RenameColumn/DropColumn` so the same code runs on
Postgres and SQLite. Add a dry-run flag that only logs the planned changes.
