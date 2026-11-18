# Missing tasks and features, in suggested implementation order

Collected on 2026-11-18 from the phase 9 documents (`_docs/phases/phase9/01`–`04`), the open items of older
phases (`phase2/02-what-is-left-from-phase1.md`, `_docs/audit/config-alignment-plan.md`) and the follow-ups left
by phases 9.1 and 9.4 (`_docs/tasks/task.md`). Items already done are not repeated here.

**Size:** S = a day or less, M = a few days, L = a week or more.
**Order rule:** cheap safety fixes first, then the foundations other work builds on (internal adapter, schema
registry), then config parity, then new features. Inside a stage, items can be done in parallel unless marked
"after …".

When an item is finished, tick it here and add a line to `task.md` like the other phases.

---

## Stage 1 – Hygiene and small security fixes (S each)

Nothing depends on these, and each one is a small, low-risk change.

- [x] **1.1 Constant-time code comparison.** `phone-number` compares OTPs with `!=`
  (`src/plugins/phone-number/services/phone_number_service.go`); use `subtle.ConstantTimeCompare` there and in
  every other code/secret comparison. *(01 §3 Timing)*
- [x] **1.2 Untrack the `example` binary** (88 MB at the repo root) and add it to `.gitignore`. *(01 §3)*
- [x] **1.3 Repo-wide `gofmt -w` in its own commit**, then fail CI on unformatted files. *(01 §3)*
- [x] **1.4 CI hardening:** `-race`, a Postgres + MySQL matrix for the repository contract tests, and a
  `golangci-lint` version that supports the module's Go version. *(01 §3)*
- [x] **1.5 Never leak repository errors.** Map unknown errors (`gorm/...`) to `500 INTERNAL_SERVER_ERROR` with
  a request ID and log the cause. *(01 §3 Graceful errors)*
- [x] **1.6 Startup validation:** fail when two plugins register the same path or operation ID, when a plugin
  dependency is missing, or when `Secret` is the dev default in production. *(01 §3)*
- [x] **1.7 One "new session" hook mechanism.** Phase 9.4 left two: core `OnNewSession` (`NewSessionHooks`
  middleware) and `pluginkit.UseAfterHook` (used by multi-session / one-time-token, which `goauth.go` has to
  initialize early). Keep one; this becomes the base of 3.3. *(9.4 follow-up)*

## Stage 2 – Foundations: internal adapter and schema registry (L)

Every later parity item (database hooks, additional fields, camelCase, MongoDB) goes through these. Order inside
the stage follows doc 04 §7.

- [ ] **2.1 `internalAdapter` equivalent** (`src/app/services/internal`): one CreateUser / UpdateUser /
  DeleteUser / CreateSession / LinkAccount / verification API used by core *and* plugins, replacing direct
  `repos.CreateUser` calls (core sign-up, email-otp, admin, org) and the duplicated delete in admin.
  *(01 §2.1)*
- [x] **2.2 Schema registry** `src/schema` with logical types only and name resolution (`ModelName`, `Fields`,
  prefix, `ColumnCase`); no GORM import. *(04 §7 step 1, 02 step 1)*
- [x] **2.3 `ParseInput` + output rules** (better-auth's additionalFields input/output rules and error codes).
  *(04 §7 step 2, 02 steps 2–3)* – after 2.2
- [x] **2.4 Generic adapter contract + memory adapter + `adapterrepo`**; run `repotest` against it. *(04 §7 step 3)*
  – after 2.2
- [ ] **2.5 GORM adapter** becomes the default `IAuthRepos` once `repotest` and the compat suite pass on SQLite,
  Postgres and MySQL; the old `gormauth` stays as an escape hatch. Riskiest step. *(04 §7 step 4)* – after 2.4
  - [x] GORM adapter (`src/adapter/gormadapter`) passing the adapter contract and `repotest` (via `adapterrepo`)
    on SQLite, Postgres and MySQL.
  - [ ] Switch `SetupGoAuth`'s default repositories to `adapterrepo(gormadapter)` and run the compat suites.
- [ ] **2.6 `additionalFields` end to end:** sign-up, update-user, update-session, plugin sign-ups, admin
  create-user; official client test with `inferAdditionalFields`. Fixes blocker B2. *(02 step 6)* – after 2.3, 2.5
- [ ] **2.7 Migrations:** SQL renderer, additive migrator, `Migrations.Mode = auto | verify | off`,
  `goauth schema` and `goauth migrate generate` (Atlas declarative/versioned/external-schema, goose,
  golang-migrate). Also replaces `PrepareLegacyColumns`. *(04 §7 step 5, phase2 open item)* – after 2.5
- [ ] **2.8 Plugins declare their schema** (`SchemaProvider`): move phone-number, two-factor, admin, username
  and anonymous columns out of `models.User`, so apps without a plugin don't get its columns. Output shows
  fields of installed plugins as `false`/`null` instead of omitting them (blocker B10). *(02 step 7, 01 §2.7)*
  – after 2.6
- [ ] **2.9 Plugins on the adapter** (`InitContext.Adapter`; deprecate `InitContext.DB`): two-factor, passkey,
  jwt, org, admin. *(04 §7 step 6)* – after 2.5

## Stage 3 – Config and behaviour parity with better-auth (M each)

These make a `betterAuth({...})` config port 1:1 and remove the remaining compatibility blockers.

- [ ] **3.1 Global rate limiter** for core and plugin routes: 100 req / 10 s default, special rules for
  `/sign-in*`, `/sign-up*`, `/change-password`, `/change-email`, `RateLimit.CustomRules`; the email-otp private
  limiter is replaced. Blocker B5. *(01 §2.5)*
- [ ] **3.2 Rate-limit storage** `memory | secondary-storage | database` (`rateLimit` table) and
  `CustomStorage`. Blocker B6. – after 3.1 and 2.7
- [ ] **3.3 Endpoint `hooks.before/after`** (`AuthConfig.Hooks` and plugin hooks) on one Huma middleware;
  rebuild `OnAfterSignIn` and the 1.7 mechanism on it. *(01 §2.3)* – after 1.7
- [ ] **3.4 `databaseHooks`** (`user/session/account/verification` × `create/update/delete` × `before/after`,
  where `before` can change or cancel), with the existing typed hooks as wrappers. Also fixes "username not
  validated on admin update-user". *(01 §2.2)* – after 2.1
- [ ] **3.5 Secret rotation:** `AuthConfig.Secrets []{Version, Value}` with `$ba$<v>$` envelopes for cookies and
  encrypted data in every plugin. Blocker B7. *(03 B7, audit plan)*
- [ ] **3.6 `onAPIError`** (`ErrorURL` replacing the hard-coded `<base>/error`, `OnError`, `Throw`). *(01 §2.4)*
- [ ] **3.7 `SocialProviders` in core** that installs the social plugin automatically, and generic-oauth providers
  registered as social providers automatically. Blocker B4.
- [ ] **3.8 Remaining organization routes:** `/organization/get-active-member`, `/get-active-member-role`,
  `/list-user-teams`. Blocker B8.
- [ ] **3.9 Update-user unknown keys:** ignore unknown fields in compat mode; plugins can mark fields as
  "cannot be updated" with their own error (`PHONE_NUMBER_CANNOT_BE_UPDATED`). Blocker B9. – after 2.3
- [ ] **3.10 Smaller core options** (S each): `trustedOrigins` as a function of the request, dynamic `baseURL`
  with `allowedHosts`, `advanced.cookies` / `defaultCookieAttributes`, `generateId: false | "uuid" | "serial"`,
  `verification.storeIdentifier` (hashed tokens), `account.storeAccountCookie`. *(03 §2, audit plan)*
- [ ] **3.11 Logger and background tasks:** injectable `AuthConfig.Logger` (levels, disabled) and
  `Advanced.BackgroundTasks` used by every `Send*` callback; add `ctx` to sender signatures in the next
  breaking release. *(01 §3)*
- [ ] **3.12 Config compat test:** build `AuthConfig` from a JSON fixture shaped like `BetterAuthOptions` and
  check keys and defaults, so drift is caught in CI. *(audit plan)* – after 3.5–3.10
- [ ] **3.13 Move older plugins onto `pluginkit`** (org, admin, jwt, access-token): one session resolver, one
  cookie manager, same CSRF/disabled-route/rate-limit handling. *(01 §2.6)*
- [ ] **3.14 Small behaviour differences:** email-otp `request-email-change` needs a fresh session; two-factor
  expired `2fa-*` row handling; social account cookie. *(03 §4)*

## Stage 4 – Shared-database compatibility (M)

Proves the "drop-in replacement" claim. Needs the foundations of stage 2.

- [ ] **4.1 `ColumnCase = camel` + `Fields`/`ModelName` mapping**, with camel the default for new installs only.
  Blocker B1. *(02 step 8, 04 §7 step 9)* – after 2.5
- [ ] **4.2 Shared-database test:** a TypeScript better-auth server and goauth on one Postgres database; sign up on
  one and sign in on the other, for core and every plugin. *(01 §4.2, phase2 open item)* – after 4.1
- [ ] **4.3 Live parity suite:** replay one request script against the TypeScript reference server and goauth,
  diff status codes, JSON shapes and cookie names in CI. *(01 §4.1)*

## Stage 5 – Cheap plugin wins (S each)

- [ ] **5.1 api-key** (`@better-auth/api-key`: keys, rate limits, permissions via the new `access` package,
  `x-api-key` session) – highest value for Go backends.
- [ ] **5.2 captcha** (Turnstile / reCAPTCHA / hCaptcha / CaptchaFox before-hook) – after 3.3
- [ ] **5.3 haveibeenpwned** (k-anonymity check on sign-up / change / reset password) – after 3.3
- [ ] **5.4 custom-session** (`/get-session` response callback)
- [ ] **5.5 last-login-method** (cookie / field updated on every sign-in) – after 1.7
- [ ] **5.6 one-tap** (Google One Tap, reuse social `VerifyIDToken`)
- [ ] **5.7 oauth-proxy** (preview deployments)
- [ ] **5.8 open-api reference** at `/api/auth/reference` (Huma already generates the document)

## Stage 6 – Larger and identity-provider features (L)

- [ ] **6.1 oidc-provider** (`/.well-known/openid-configuration`, `/oauth2/authorize`, `/consent`, `/token`,
  `/userinfo`, `/register`, `/endsession`; pairs with jwt)
- [ ] **6.2 mcp** (OAuth authorization server for MCP clients) – after 6.1
- [ ] **6.3 device-authorization** (RFC 8628, for CLIs and TVs)
- [ ] **6.4 SSO** (SAML/OIDC per organization), then **6.5 SCIM** provisioning – after 6.1
- [ ] **6.6 siwe** (Sign-In with Ethereum) – niche, last

## Stage 7 – Other databases (L, when needed)

- [ ] **7.1 `database/sql` adapter** (covers Bun, sqlx, pgx, sqlc and Ent apps). *(04 §7 step 7)* – after 2.9
- [ ] **7.2 MongoDB adapter** with partial unique indexes for nullable unique fields, TTL indexes and ObjectId/UUID
  IDs. *(04 §7 step 8)* – after 2.9
- [ ] **7.3 Extra schema renderers:** `atlas-hcl`, `ent`, `go`, `prisma`. *(04 §7 step 9)* – after 2.7
- [ ] **7.4 Plugin repository contract tests** (two-factor, passkey, org) like `repotest`, and fuzz tests for
  cookie parsing, OAuth state decoding and WebAuthn payloads. *(01 §4.3–4.4)*

---

## Decisions to make (no code until decided)

These come from older phases and change behaviour for existing users, so they need a decision first:

| Decision | Options | Source | Decided (2026-11-18) |
|---|---|---|---|
| User soft delete (`deletedAt`) | keep (goauth) or hard delete with cascade like better-auth, audit via an after-delete hook | phase2 open item | **Done:** config `User.GoAuth.SoftDelete`, default `false` = better-auth hard delete with cascade |
| Default ID format | 32-char random like better-auth, or keep ULID (`models.SetIDGenerator`) | phase2 open item | **Done:** config `Advanced.Database.IDFormat` (`random` default, `uuid`, `ulid`); `GenerateID` func still wins |
| Legacy `/login`, `/refresh` routes | move into the JWT transport and deprecate, or keep | phase2 open item | **Done:** they stay in the access-token plugin; the leftover JWT code in core moved there or was removed |
| Legacy user fields (`user.active` / `accountStatus`) | fold into `banned` / `banReason` / `banExpires` | phase2 open item | **Done:** the fields were already gone; the unused `AccountStatus` enum and `models.UserFilter/UserQuery` were removed |
| Org `status` / `createdBy` approval workflow | becomes opt-in additional fields once 2.6 exists | phase2 open item | **Keep for now** |
| camelCase default | new installs only, or opt-in everywhere | 04 §8 | open (see 4.1) |
| Old Go config field names | keep as aliases for one minor version with a warning | audit plan | open |
