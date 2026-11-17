# 01 – Robustness and parity improvements

Concrete changes to existing code that make goauth safer and closer to better-auth's behaviour.
Each item names the file, the problem, and the fix. Items are ordered by priority inside each section.

Reference implementation: better-auth v1.6.16 (sources in `src/tests/compat/client/node_modules/better-auth/dist`).

---

## 1. Correctness and security fixes (do first)

> **Status: done (phase 9.1).** See `_docs/tasks/task.md` for what was implemented. Notes: 1.2 follows
> better-auth exactly (every read deletes *all* expired rows); 1.4 uses an atomic read-modify-write
> capability (`sec_storage.AtomicUpdater`) instead of a sorted set, so the JSON key stays readable by a
> TypeScript server; 1.7's missing-query case was already handled.

### 1.1 Admin "remove user" leaves the phone number locked
- **Where:** `src/plugins/admin/repository/gorm/admin_repo.go` `RemoveUser`.
- **Problem:** It duplicates the core soft delete but only rewrites the email. The unique `phone_number`
  stays on the tombstone row, so the number can never be registered again. (`AdminService.RemoveUser` does
  fire `UserDeleted`, so two-factor and passkey rows are cleaned up.)
- **Fix:** Call the core `IUserRepo.DeleteUser` (which already clears `PhoneNumber`) instead of a private copy,
  inside the same transaction as the account delete. Add a test: admin removes a user with a phone and a
  passkey → number reusable, passkey rows gone.

### 1.2 Expired verification rows are never cleaned up
- **Where:** `config.VerificationOptions.DisableCleanup` exists but nothing calls `DeleteExpiredVerifications`
  (the only caller is commented out in the access-token plugin). Same for `DeleteExpiredSessions`
  (`Manager.CleanupExpired` exists but is never scheduled).
- **better-auth:** `findVerificationValue` deletes expired rows for the identifier on read, unless
  `verification.disableCleanup` is set.
- **Fix:** In `FindVerificationValue` callers (or a repo decorator), delete expired rows on read when cleanup is
  enabled. Add an optional `GoAuth.Cleanup.Interval` background ticker (`(*GoAuth).StartCleanup(ctx)`) that
  calls both `DeleteExpired*` methods; off by default, documented for long-running servers.

### 1.3 OTP attempt counters are not atomic
- **Where:** every "code:attempts" flow (email-otp `verifyOTPAttempt`, phone-number verify/reset, two-factor OTP).
- **Problem:** read → compare → re-insert with `attempts+1` is a read-modify-write. N parallel wrong guesses
  all read `attempts=0`, so the limit can be exceeded by the request concurrency. `UpsertVerificationValue`
  also deletes and re-creates the row, changing its `id`.
- **Fix:** add `UpdateVerificationValue(ctx, id, oldValue, newValue) (bool, error)` to `IVerificationRepo`
  implemented as `UPDATE verification SET value=? WHERE id=? AND value=?` (compare-and-swap). Callers retry
  or fail when it returns false. Successful verification should use `ConsumeVerificationValue` (atomic delete)
  instead of verify-then-delete, so a code can never be used twice concurrently.
  better-auth does this for magic links (`consumeVerificationValue`) and its email-otp `atomicVerifyOTP`.

### 1.4 Active-session index race in secondary storage
- **Where:** `src/app/services/session/manager-sec-store.go` `trackActive` / `untrackActive`.
- **Problem:** documented already (BUG-08): read-modify-write of `active-sessions-<userId>` loses entries
  across processes; the in-process mutex only helps a single instance.
- **Fix:** add an optional `AtomicList` capability to `SecondaryStorage`
  (`ZAdd/ZRem/ZRangeByScore` on Redis, mutex on memory). Use it when the store implements it, keep the JSON
  list as the fallback so the key format stays better-auth compatible.

### 1.5 Mutating plugin routes without an origin check
- **Where:** org, admin, jwt and access-token plugins register routes with raw `huma.Register`.
- **Problem:** better-auth runs `originCheckMiddleware` on every POST. Only core routes and the plugins built on
  `pluginkit` get it; the others rely on `Security.CheckOriginOnPluginMutations` (off by default).
- **Fix:** migrate those plugins to `pluginkit.Register` (or at least add `humaadapter.OriginCheck` to their
  middlewares), then flip `CheckOriginOnPluginMutations` to default-on.

### 1.6 Account uniqueness differs from better-auth
- **Where:** `models.Account` has `uniqueIndex:idx_user_provider` on `(user_id, provider_id)`.
- **Problem:** better-auth has no such constraint; a user may link two accounts of one provider (two GitHub
  identities) and SSO / generic-oauth plugins rely on that. A TypeScript server sharing the database can
  therefore fail inserts that it expects to succeed.
- **Fix:** replace it with a unique index on `(provider_id, account_id)` only (already present as
  `idx_provider_account`) and make `FindAccountByUserAndProvider` return the oldest match. Add a migration that
  drops `idx_user_provider`.

### 1.7 Error responses that are not better-auth shaped
- Validation failures for a missing query parameter (e.g. magic-link `token`) come from Huma, not as
  `400 {"code":"VALIDATION_ERROR"}`. Map Huma's 422/400 for query/path params through the same
  `types.NewError` override used for bodies.
- `FAILED_TO_CREATE_USER` is registered as 422 in core but better-auth returns 500 for it in most plugins.
  Audit `src/common/autherr/better_auth_codes.go` statuses against `@better-auth/core/error` and keep a test
  that compares every code, message and status (`testdata/base_error_codes.json` already exists; extend it
  with statuses).

---

## 2. Making the internals look like better-auth

### 2.1 An `internalAdapter` equivalent
better-auth funnels all writes through `internalAdapter` (createUser, createSession, linkAccount,
updateUser…), which is where `databaseHooks`, `additionalFields` parsing, secondary storage and the cookie
cache are applied. goauth spreads this across repositories, `session.Manager`, `auth.Service` and now
`pluginkit.Kit`.

**Recommendation:** promote `pluginkit.Kit`'s user/session helpers into a core `internal` service
(`src/app/services/internal`), used by core *and* plugins:

```go
type InternalAdapter interface {
    CreateUser(ctx, *models.User) (*models.User, error)          // database hooks, additional fields
    UpdateUser(ctx, id string, patch UserPatch) (*models.User, error) // + refresh cached sessions
    DeleteUser(ctx, id string) error                               // + accounts, sessions, UserDeleted
    CreateSession(ctx, userID string, opts SessionOptions) (*dtos.SessionWithUser, error)
    LinkAccount(ctx, *models.Account) (*models.Account, error)
    CreateVerification / FindVerification / ConsumeVerification / UpdateVerification
}
```

Every place that calls `repos.CreateUser` directly today (core sign-up, email-otp, admin create-user,
org) would go through it, so hooks and future additional fields apply uniformly. This also removes the
duplicated delete logic from the admin plugin (1.1).

### 2.2 `databaseHooks` instead of ad-hoc hook methods
`HookRegistry` has fixed methods (`BeforeUserCreate`, `UserBanned`, `ActiveOrgChanged` …). better-auth exposes
generic `databaseHooks.{user,session,account,verification}.{create,update,delete}.{before,after}` where
`before` can modify or cancel the data. Add a generic layer on top of the existing registry:

```go
type DatabaseHooks struct {
    User         ModelHooks[models.User]
    Session      ModelHooks[models.Session]
    Account      ModelHooks[models.Account]
    Verification ModelHooks[models.Verification]
}
type ModelHooks[T any] struct {
    Create, Update, Delete Stage[T]
}
type Stage[T any] struct {
    Before func(ctx context.Context, data *T) (cancel bool, err error)
    After  func(ctx context.Context, data *T) error
}
```

Expose it as `AuthConfig.DatabaseHooks` and let plugins append. The existing typed methods become thin
wrappers, so nothing breaks.

### 2.3 Endpoint `hooks.before / hooks.after`
better-auth's top-level `hooks` (and every plugin's `hooks`) run middleware matched by path, with access to the
request body and the produced response (`ctx.context.returned`, `newSession`). goauth's `OnAfterSignIn`
interceptor is a special case of this. Generalise it:

```go
type EndpointHook struct {
    Matcher func(path string) bool
    Before  func(ctx context.Context, r *EndpointRequest) (*EndpointResponse, error) // non-nil = short-circuit
    After   func(ctx context.Context, r *EndpointRequest, res *EndpointResponse) (*EndpointResponse, error)
}
```

Implement once as a Huma API middleware installed in `SetupGoAuth` before routes are registered. It needs a
response recorder around `huma.Context` (the bearer plugin already wraps the response writer; reuse that
code). Then rebuild `OnAfterSignIn` on top of it and port the two-factor matcher to the generic form.

### 2.4 `onAPIError`
Add `AuthConfig.OnAPIError { Throw bool; OnError func(err error, r *http.Request); ErrorURL string }`.
`ErrorURL` replaces the hard-coded `<base>/error` in redirects (social callback, magic link, verify-email);
`OnError` lets apps log or report 5xx errors.

### 2.5 One rate limiter for everything
`src/providers/ratelimit` is used only by the new plugins; email-otp has its own limiter and core routes have
none. better-auth applies a global default (100 req / 10 s in production) plus special rules
(`/sign-in*`, `/sign-up*`, `/change-password`, `/change-email`: 3 / 10 s) and plugin rules.
- Install one Huma middleware in `SetupGoAuth` that resolves the rule per path from
  `RateLimit.CustomRules`, plugin-declared rules, the special rules and the global default.
- Replace the email-otp private limiter with it (keep its config as the plugin rule).
- Support `RateLimit.Storage = "memory" | "secondary-storage" | "database"` (a `rateLimit` table, as in
  better-auth) and `RateLimit.CustomStorage`.

### 2.6 Consistent plugin structure
The org/admin/jwt/access-token plugins each have their own handler helpers, cookie managers and session
resolution (`getSession` in email-otp checks five sources). Moving them onto `pluginkit` gives: one session
resolver, one cookie manager instance (fixes signing-secret drift), the same CSRF rules, disabled-route
handling and rate limiting.

### 2.7 Plugin schema declaration
Plugins currently add columns by editing `models.User` (role/banned, phone, two-factor). better-auth plugins
declare a `schema` that is merged into the core schema. With the dynamic-columns work
([02-dynamic-columns-plan.md](02-dynamic-columns-plan.md)) plugins should declare fields through the same
registry so users who don't install the phone-number plugin don't get a `phone_number` column.

---

## 3. Operational robustness

| Area | Change |
|---|---|
| Startup validation | `SetupGoAuth` should fail fast when two plugins register the same path/operation ID, when a plugin depends on another (two-factor → phone-number sign-in path) or when `Secret` is the dev default in production. |
| Graceful errors | Never return raw repository errors (`fmt.Errorf("gorm/…")`) to clients; map unknown errors to `500 INTERNAL_SERVER_ERROR` with a request ID and log the cause. |
| Logging | Replace scattered `slog.Warn` with an injectable `Logger` (`AuthConfig.Logger`, levels like better-auth's `logger.level`), including a `disabled` option for tests. |
| Background tasks | better-auth's `advanced.backgroundTasks.handler` lets senders (email, SMS) run without blocking the response. Add `Advanced.BackgroundTasks func(task func())`; use it for every `Send*` callback. |
| Timing | Compare all secrets/codes with `subtle.ConstantTimeCompare` (`src/plugins/phone-number/services/phone_number_service.go` compares OTPs with `!=`, mirroring better-auth; there is no reason to keep that). |
| Context | Pass `ctx` everywhere instead of `context.Background()`; some sender callbacks receive only `*http.Request`. Add `ctx` to callback signatures in the next breaking release. |
| Repo binary | `example` (88 MB executable) is committed at the repo root; untrack it and add it to `.gitignore`. |
| CI | The workflow now runs the whole suite; add `-race`, a Postgres + MySQL matrix for the repository contract, and pin `golangci-lint` to a version that supports the module's Go version. |
| Formatting | Many files are not `gofmt`-clean; run `gofmt -w` once in a separate commit and enforce it in CI. |

---

## 4. Test strategy improvements

1. **Golden parity suite against a live better-auth server.** `_docs` mentions `better-auth-schema` (a
   TypeScript reference server). Run it in CI (Node + SQLite), replay the same request script against both
   servers, and diff status codes, JSON shapes (keys and types, not values) and cookie names. This catches
   drift automatically instead of by reading source.
2. **Shared-database test.** Point the TypeScript server and goauth at the same Postgres database; sign up on
   one, sign in on the other, for every plugin. This is the real definition of "full compatibility".
3. **Contract tests for every plugin repository** (two-factor, passkey, org), like `repotest` for core.
4. **Fuzz tests** for cookie parsing (`cookies.ReadSigned`), state decoding (social plugin) and WebAuthn
   payload parsing.
