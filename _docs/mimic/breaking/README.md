# Breaking path – goauth on a new project

The non-breaking work keeps old databases and the legacy JWT API running: models list the
better-auth fields first, then goauth extras, then fields marked `to be deleted`.
This document covers what comes next if backward compatibility doesn't matter (a new project, no existing rows).
Steps are ordered so each one builds on the previous.

## 1. Delete the marked fields

| model | delete | replacement |
|---|---|---|
| `Session` | `SessionId` | `session.id` is the JWT `sid` claim |
| `Session` | `Blacklisted`, `BlacklistedOn`, `RevokedAt` | revoking = deleting the row (plus secondary-storage entry) |
| `Session` | `Role` | read `user.role` when issuing tokens |
| `User` | `ActiveOrgId` | `session.activeOrganizationId` |
| `OrgPermission` (table) | whole table | `organizationRole` (step 9) |

After this there is one session model: a better-auth session row. The legacy JWT flow becomes a
transport on top of it (step 6), not a second kind of session.

## 2. better-auth table names

`auth_users` → `user`, `auth_sessions` → `session`, `auth_accounts` → `account`,
`auth_verifications` → `verification`, `organizations` → `organization`, `members` → `member`,
`invitations` → `invitation`. Keep a `Schema.TablePrefix` option for users who need to avoid name clashes
(`user` is a reserved word in Postgres; GORM quotes it, raw SQL must too).

## 3. camelCase columns

- Add an explicit `gorm:"column:emailVerified"` tag to every field, and declare the column names as constants per model.
- Replace the raw strings in the repos (`Where("user_id = ?")`, `Order("created_at desc")`, `map[string]any{"status": ...}`).
  Use struct conditions, `clause.Eq` / `clause.OrderByColumn`, and Go field names as map keys.
- Accept sort fields only from an allowlist (API name → column). Never concatenate them into `Order`.
- Name indexes explicitly (`uniqueIndex:user_email_key`) so they don't depend on the table name.

## 4. Types and constraints

- `user.email`: `string`, not null, unique, lowercased on write.
- `user.image`: `*string`.
- `Base.CreatedAt/UpdatedAt`: `time.Time` (not pointers), JSON `createdAt` / `updatedAt`.
- Foreign keys with `ON DELETE CASCADE`: `session.userId`, `account.userId`, `member.userId`,
  `member.organizationId`, `invitation.organizationId`, `invitation.inviterId`.
- Drop user soft delete (`deletedAt`), because better-auth deletes users and cascades.
  If an audit trail is needed, use an `afterDelete` hook that writes to an audit table.

## 5. Role and status values

- `user.role`: default `user`, lowercase (`admin`, `user`), comma-separated for multiple roles. Drop `UNVERIFIED_PERSON`;
  `emailVerified` already carries that.
- `user.active` / `accountStatus`: fold into the admin plugin's `banned` / `banReason` / `banExpires`.
- Member role `org_admin` → `admin`.
- Organization `status` / `createdBy` (approval workflow): keep as an opt-in goauth extension and register
  them as `additionalFields`, so the TypeScript side can be told about them if both servers share the DB.

## 6. Sessions and tokens

- Sign-in creates a better-auth session (32-char token, sliding expiry, cookie cache).
- JWT access/refresh tokens become an opt-in plugin (like better-auth's `bearer` + `jwt` plugins):
  - the refresh token is the session token;
  - the access token is a short-lived JWT whose `sid` is `session.id`;
  - refresh = look up the session by token, apply sliding expiry, mint a new JWT.
- `Session.Token` hashing (`SHA-256`) stays an option, off by default, so a TypeScript server can read the same rows.

## 7. Passwords and IDs

- Passwords live only on the `credential` account, scrypt by default (bcrypt only via a custom hasher).
- IDs: better-auth's 32-char random alphanumeric (`idgen.GenerateID`) by default; ULID as an option.

## 8. API surface

- Delete the `compat` package:
  - move the error codes to `src/common/errors`;
  - have the models serialize to better-auth's JSON shapes, so the separate DTOs go away.
- Only better-auth routes and bodies (`/sign-in/email`, `/get-session`, …). Errors always `{code, message}`.
  Drop the legacy `/login`, `/refresh` etc. or move them into the JWT plugin from step 6.

## 9. Organization plugin parity

- Teams: `team`, `teamMember`, `session.activeTeamId`, `invitation.teamId`.
- Dynamic access control: an `organizationRole(id, organizationId, role, permission JSON, createdAt, updatedAt)` table,
  plus `has-permission` / role CRUD endpoints.
  - `OrgPermissionsMap` becomes the default statement set, with roles resolved per org.
  - `RequireOrgMember` checks permissions (`member: ["update"]`) instead of role names.
- Every authorization check stays in the handlers (already done), so this is a swap of the checker only.

## 10. Verification

- Use better-auth's identifiers and values (`reset-password:<token>` → userId, email verification via a signed JWT).
- Keep goauth's 6-digit codes as an extension with their own identifier prefix.

## 11. Migrations

- Replace `AutoMigrate` with versioned SQL migrations (Atlas or goose).
  Generate the baseline from better-auth's CLI (`npx @better-auth/cli generate`) and add goauth extras on top.
- Delete `PrepareLegacyColumns` and the other upgrade code.
- MySQL: open GORM with `mysql.Config{DefaultStringSize: 191}` (or give indexed columns a size).
  Without it, unsized strings become `longtext`, which can't be indexed or used as a foreign key.

## 12. Cross-implementation tests

Run the TypeScript test server (`better-auth-schema/`) and goauth against the same Postgres database:
- sign up in one and sign in on the other;
- check that cookies issued by one validate on the other;
- compare `get-session`, `list-sessions` and org endpoints field by field.

This becomes the regression suite for every later change.
