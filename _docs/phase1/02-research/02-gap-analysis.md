# 02 – Gap analysis (what goauth is missing)

Severity: **B** = blocks wire compatibility · **H** = high (feature parity) ·
**M** = medium · **L** = low / nice to have.
Effort: S (≤ 1 day) · M (2–5 days) · L (1–2 weeks) · XL (> 2 weeks).

## A. Contract / wire-format gaps

| # | Gap | Where in goauth | Sev | Effort |
|---|---|---|---|---|
| A1 | Responses wrapped in `GResp{body,status,rows_affected,…}`; better-auth returns raw JSON | `src/common/dtos/resp_dto.go`, all handlers | B | M |
| A2 | Error body is GResp or Huma problem+json; better-auth is `{code,message}` with string codes (`INVALID_EMAIL_OR_PASSWORD`) | `src/common/errors/*`, `src/common/types/override-huma.go` | B | S |
| A3 | Route names differ (`/signup`, `/login`, `/logout`, `/refresh`, `/forgot_password`, `/profile/*`, `/session/*`) | `src/app/core/*/…routes.go` | B | M |
| A4 | Request field names differ (`info`, `firstName`, `new_password`, `device_token`) | `auth.models.go`, `models/dto.auth.go` | B | S |
| A5 | No `get-session` endpoint (the most used client call) | – | B | M |
| A6 | JSON casing inconsistent (`created_at`, `org_id`, `last_seen`, `user_data`, `auth_tokens`) | `models/common.go` `Base`, `models/auth.user.go` | B | S |
| A7 | No `/ok`, `/error` | – | L | S |

## B. Session / token gaps

| # | Gap | Sev | Effort |
|---|---|---|---|
| B1 | Uses JWT access/refresh pair; better-auth uses opaque session token with sliding expiry | B | L |
| B2 | No signed `{prefix}.session_token` cookie (HMAC-SHA256) | B | S |
| B3 | No `Secret`/`BaseURL`/`AppName`/`TrustedOrigins`/`CookiePrefix` top-level options (only `SessionConfig.AccessSecret`) | B | S |
| B4 | Session model lacks `token`, `ipAddress`, `userAgent`; has `SessionId`, `HashedToken`, `Role`, `Blacklisted` | B | M |
| B5 | `ExpiresIn`, `UpdateAge`, `FreshAge`, `DisableSessionRefresh`, `StoreSessionInDatabase` declared but unused | H | M |
| B6 | No cookie cache (`session_data`) compact/jwt/jwe | H | M (port) |
| B7 | No `rememberMe` / `dont_remember` | H | S |
| B8 | Secondary storage used only for revocation, not session storage (key layout must match better-auth for shared Redis) | H | M |
| B9 | Middleware authenticates JWT bearer only, no cookie path | B | M |
| B10 | No stateless (no-DB) mode | M | M |

## C. Data model gaps

| # | Gap | Sev | Effort |
|---|---|---|---|
| C1 | User has `firstName/lastName`, no `name` | B | S |
| C2 | Password duplicated on `user.password` and `account.password` | H | S |
| C3 | Table names `auth_*` and snake_case columns; better-auth defaults to `user/session/account/verification` with camelCase columns | H (DB compat) | M |
| C4 | Role values `User`/`Admin`, DB default `UNVERIFIED_PERSON`; better-auth uses lowercase `user`/`admin`, comma-separated multi-role | H | S |
| C5 | Verification requires `UserId`, identifier is unique, value hashed | H | S |
| C6 | `Active`, `AccountStatus`, `ActiveOrgId` on user (goauth-only) – need to become optional extension fields | M | S |
| C7 | No `additionalFields` mechanism | H | L |
| C8 | No pluggable `GenerateID` | L | S |
| C9 | No data migration path from current goauth schema | H | M |

## D. Crypto gaps

| # | Gap | Sev | Effort |
|---|---|---|---|
| D1 | bcrypt **MinCost** in production code (security issue regardless of compat) | B | S |
| D2 | No scrypt hasher compatible with better-auth `salt:hex` format | B (DB compat) | S |
| D3 | No custom hasher wiring (`EmailAndPassword.Password` is commented out) | H | S |
| D4 | Email verification uses stored codes; better-auth uses HS256 JWT in a link | H | S (port) |
| D5 | No symmetric encryption helper (for `encryptOAuthTokens`, jwks private keys) | M | S |

## E. Feature gaps (core)

| # | Gap | Sev | Effort |
|---|---|---|---|
| E1 | `EmailAndPassword` options (`Enabled`, `DisableSignUp`, `RequireEmailVerification`, `AutoSignIn`, `Min/MaxPasswordLength`, `RevokeSessionsOnPasswordReset`, `SendResetPassword`, `OnPasswordReset`, `OnExistingUserSignUp`) declared but not enforced | H | M |
| E2 | `EmailVerification` options (`SendVerificationEmail`, `SendOnSignUp`, `SendOnSignIn`, `AutoSignInAfterVerification`, `Before/AfterEmailVerification`) missing | H | M |
| E3 | Delete-user flow (`user.deleteUser.enabled`, `sendDeleteAccountVerification`, `beforeDelete/afterDelete`) | H | M |
| E4 | Change-email flow with `user.changeEmail.enabled`, `sendChangeEmailVerification` | H | M |
| E5 | Social sign-in, callback, account linking (`account.accountLinking`) | H | XL |
| E6 | `/verify-password`, `/update-session`, `/revoke-*` | H | S |

## F. Security gaps

| # | Gap | Sev | Effort |
|---|---|---|---|
| F1 | No trusted origins / origin check | H | M |
| F2 | No CSRF fetch-metadata check | H | S |
| F3 | No callbackURL / redirectTo validation (open redirect risk) | H | S |
| F4 | No rate limiter | H | M |
| F5 | No IP extraction config (`advanced.ipAddress`) | M | S |
| F6 | No `disabledPaths` | L | S |

## G. Extensibility gaps

| # | Gap | Sev | Effort |
|---|---|---|---|
| G1 | No generic database hooks (`databaseHooks.{user,session,account,verification}.{create,update,delete}.{before,after}`) | H | M |
| G2 | No request hooks (`hooks.before/after` with path matchers) | H | M |
| G3 | Plugin interface lacks `Schema`, `Hooks`, `RateLimit`, `ErrorCodes`, `OnRequest/OnResponse` | H | M |
| G4 | Dead/typo duplicate types in `src/plugins/plugin.go` (`InitContex`, `Plugi`, `RouteDescripto`) | L | S |
| G5 | Plugin routes registered with plugin-specific base paths, not normalised under `BasePath` | M | S |

## H. Plugin gaps

See [05-plugins.md](../03-spec/05-plugins.md). Summary:

- **admin** – missing `/admin/get-user`, `/admin/update-user`, `/admin/has-permission`;
  `/admin/set-user-role` must be `/admin/set-role`; `list-users` must be `GET` with
  query (`searchValue`, `searchField`, `searchOperator`, `limit`, `offset`, `sortBy`,
  `sortDirection`, `filterField`, `filterValue`, `filterOperator`) and return
  `{users,total,limit,offset}`; impersonation must set `session.impersonatedBy`
  and an `admin_session` cookie.
- **organization** – roles `owner/admin/member` (goauth uses `org_admin`); delete is
  `POST`; missing teams, dynamic roles, `check-slug`, `leave`, `get-active-member`,
  `get-active-member-role`, `has-permission`, `list-user-invitations`; active org
  must live on `session.activeOrganizationId`; `status`/`createdBy` are goauth extensions.
- Everything else (two-factor, username, magic-link, email-otp, phone-number,
  anonymous, bearer, jwt, api-key, passkey, multi-session, …) is missing.

## I. Things goauth has that the others don't (keep as extensions)

| Feature | Keep as |
|---|---|
| Operation-ID RBAC (`OperationAccessDto`, `Authorize(opId, roles)`) | `goauth/ext/rbac` – opt-in middleware |
| Org approve/block/unblock + org `status` | org plugin option `RequireApproval`; routes under `/organization/admin/*` (non-conflicting) |
| `deviceToken` on session (push) | `session.additionalFields` |
| `AccountStatus`, `Active` | `user.additionalFields` + DB hook |
| JWT access/refresh flow | Legacy mode until v3, then removed (replaced by `bearer` + `jwt` plugins) |
| Huma OpenAPI | Keep; better-auth has an `open-api` plugin – match its operation IDs later |
