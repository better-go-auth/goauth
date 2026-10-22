# Config Alignment Plan — goauth vs Better Auth (`options.d.ts`)

> **Sources inspected:** `_docs/audit/options.d.ts` (BetterAuthOptions, 886 LOC) vs `src/config/{config,options,session-config,email-and-password,email-verification,user}.go` + `goauth.go` (GoAuthOptions) + `src/plugins/*/config/config.go` + `_docs/phase1/03-spec/04-config.md`.
> **Rule from spec 04-config:** every better-auth option keeps its PascalCase name and meaning; anything goauth-only goes into a `GoAuth` sub-struct of the same section so a reader can always tell which options are upstream. Durations use `time.Duration` instead of seconds — keep that convention.

## 1. Snapshot: what Better Auth exposes at the top level

```ts
type BetterAuthOptions = {
  appName, baseURL, basePath, secret, secrets,
  database, secondaryStorage,
  emailVerification, emailAndPassword, socialProviders, plugins,
  user, session, account, verification,
  trustedOrigins, onAPIError, hooks,
  disabledPaths, telemetry, experimental,
  advanced, rateLimit  // rateLimit & advanced are top-level in TS too
}
```

Commented-out sections in `options.d.ts` (`baseURL`, `secondaryStorage`, `socialProviders`, `plugins`, DB options, `hooks`, `onAPIError`) are still part of the contract — they are only commented because the audit file stubs `User`/`Session`.

## 2. Snapshot: what goauth core exposes today

```go
// src/config/config.go
type AuthConfig struct {
  AppName, BaseURL string, BasePath, Secret string
  TrustedOrigins []string
  DisabledPaths  []string
  Advanced       Advanced
  EmailAndPassword  EmailAndPassword
  EmailVerification EmailVerification
  Session           Session
  User              UserOptions
  Account           AccountOptions
  Verification      VerificationOptions
  RateLimit         RateLimitOptions
  GoAuth GoAuthConfig // Mode, Session SessionGoAuth, TablePrefix, TableNames
  // + cached fields (cachedSecure, cachedCookieDomain, cachedDomainOnce)
}
// goauth.go
type GoAuthOptions struct {
  config.AuthConfig
  Conn *gorm.DB; Repositories repo_interfaces.IAuthRepos
  Migrator migration.IMigrator; TxManager interfaces.ITransactionManager
  SecondaryStorage sec_storage.SecondaryStorage
  Plugins []plugin.Plugin
}
```

Plugin-owned configs (`src/plugins/*/config`) are **not** core — they stay plugin-scoped. They are only referenced here to show where some better-auth concepts already live outside core.

## 3. Gap matrix (core only)

| Section | Status | Missing / Divergent |
|---|---|---|
| **Top-level** | partial | `secrets` (versioned rotation) missing; `database` missing from `AuthConfig`; `secondaryStorage` only on `GoAuthOptions` not `AuthConfig`; `socialProviders`/`plugins` not on `AuthConfig` (by design — goauth uses `GoAuthOptions.Plugins`, but needs a `SocialProviders` passthrough if compat mode wants to mirror the key); `hooks`, `onAPIError` completely absent; `telemetry`, `experimental` absent |
| **BaseURL** | divergent type | TS: `string \| { allowedHosts: string[], fallback: string }`; Go: `string` only |
| **TrustedOrigins** | divergent type | TS: `string[] \| ((req?) => string[])` with wildcard support; Go: `[]string` only |
| **Advanced** | partial | Has: `CookiePrefix`, `UseSecureCookies`, `CrossSubDomainCookies`, `DisableCSRFCheck`, `DisableOriginCheck`, `IPAddress`, `Database.GenerateID`, `GoAuth.OverrideHumaErrors`. Missing: `cookies` (per-cookie overrides), `defaultCookieAttributes`, and full `IPAddress` field names (`ipAddressHeaders` vs `Headers`, `disableIpTracking` vs `DisableTracking`). |
| **Session** | missing major sub-object | Missing entire `cookieCache { enabled, maxAge, strategy, refreshCache, version }` (defined in TS, enum `compact|jwt|jwe`). Go has `CookieCacheStrategy` constants but no struct field. Also missing `additionalFields`/`modelName`/`fields` extensibility. `StoreSessionInDatabaseSet` sentinel is goauth-only — keep it but document. |
| **EmailAndPassword** | mostly aligned, 1 missing callback | Missing `customSyntheticUser` (currently commented out in `email-and-password.go:115`). `RehashPasswords` sits at top level of `EmailAndPassword` — per spec it belongs in `EmailAndPassword.GoAuth`. `password.hash/verify` signature uses `(string) -> (string,error)` in Go vs `(string) -> Promise<string>` in TS — acceptable, but document. `autoSignIn`/`enabled` are `*bool` in Go (nil = default) vs `boolean` in TS — keep pointer but note. |
| **EmailVerification** | aligned + goauth extension | Core fields match. Go extension `GoAuth { CodeSender, CodeGenerator, CodeExpiresIn }` is intentional (6-digit code flow) — keep. No gap. |
| **User** | aligned | Matches TS (`changeEmail`, `deleteUser`). Missing TS DB extensibility: `modelName`, `fields`, `additionalFields`. Spec 04-config expected those — defer to DB/plugin layer if not wanted now. |
| **Account** | severely stripped | Go has only `AccountLinking.AllowUnlinkingAll`. Missing: `updateAccountOnSignIn`, `encryptOAuthTokens`, `skipStateCookieCheck`, `storeStateStrategy`, `storeAccountCookie`, and 6/7 `accountLinking` flags (`enabled`, `disableImplicitLinking`, `requireLocalEmailVerified`, `trustedProviders`, `allowDifferentEmails`, `updateUserInfoOnLink`) plus `modelName`/`fields`. |
| **Verification** | stripped | Go has `DisableCleanup` only. Missing: `storeIdentifier` (`plain|hashed|{hash}` + per-type overrides), `storeInDatabase`, `modelName`/`fields`. |
| **RateLimit** | partial | Go: `Enabled, Window, Max, Storage string`. Missing: `customRules`, `modelName`, and `storage` as `SecondaryStorage` vs string. TS also supports a plugin-provided storage adapter. |
| **Hooks / onAPIError** | absent | No `hooks { before, after }` and no `onAPIError { throw, onError, errorURL }` on `AuthConfig`. |
| **Telemetry / Experimental** | absent | No `telemetry { enabled, debug }`, no `experimental { joins }`. |
| **Verification / Session / User DB hooks** | absent | No `databaseHooks` / `DatabaseHooks` top-level key from spec. |

## 4. Detailed section notes

### 4.1 Top-level — `secrets`, `database`, `secondaryStorage`

- **Better Auth:** `secret` is legacy single key; `secrets: { version, value }[]` is the envelope-rotation format (first entry = current). Env `BETTER_AUTH_SECRETS=2:xxx,1:yyy`. `database` carries `dialect/type/casing/debugLogs/transaction` or a `Kysely` instance. `secondaryStorage` is a `SecondaryStorage` adapter (get/set/delete) used for session + rate-limit.
- **Goauth today:** `Secret string` + `DeriveKey` helper only. `database` is implicit via `GoAuthOptions.Conn *gorm.DB` / `Repositories` / `Migrator` / `TxManager`. `secondaryStorage` is only on `GoAuthOptions` as `sec_storage.SecondaryStorage`.
- **Mismatch effect:** compat consumers that pass `secrets` or `database: { casing, debugLogs, transaction }` have nowhere to put it; secret rotation cannot be configured.

### 4.2 `baseURL` / `trustedOrigins`

- TS `baseURL` supports `{ allowedHosts, fallback }` for multi-tenant / Vercel preview deployments. Go validates `BaseURL` as absolute URL and caches `SecureCookies`/`CookieDomain` from it — no `allowedHosts` path.
- TS `trustedOrigins` can be `string[] | (req => string[])` with `*.example.com` wildcards. Go stores `[]string` and `origin.New()` checks them statically.

### 4.3 `advanced`

- TS `advanced` includes `cookies` (per-cookie name/attributes overrides), `defaultCookieAttributes` (SameSite, partitioned, etc.), plus `disableCSRFCheck`/`disableOriginCheck` which goauth already has. Go's `Advanced.GoAuth.OverrideHumaErrors` matches spec placement — keep it.
- IP address: TS is `ipAddress: { ipAddressHeaders, disableIpTracking, ipv6Subnet }`; Go is `IPAddress: { Headers, DisableTracking, IPv6Subnet }`. Names differ; wire mapping needs alias or doc.

### 4.4 `session` — biggest gap

TS `session` (lines ~394–521):
```
expiresIn, updateAge, disableSessionRefresh, deferSessionRefresh,
storeSessionInDatabase, preserveSessionInDatabase,
cookieCache { enabled, maxAge, strategy: compact|jwt|jwe, refreshCache, version },
freshAge
+ modelName/fields/additionalFields
```
Go `Session` (session-config.go) has everything except `cookieCache` and DB extensibility. Constants `CookieCacheStrategyCompact/Jwt/Jwe` exist but are unused. `SessionGoAuth` (`SingleSession`, `UpdatableFields`, plugin JWT) is intentionally goauth-only and per spec should live at `Session.GoAuth` / `GoAuth.Session` — today it lives at both `AuthConfig.GoAuth.Session` and `plugins/access-token/config.SessionGoAuth`, which is duplicated.

### 4.5 `emailAndPassword`

- Fully aligned except `customSyntheticUser` is commented out (`email-and-password.go:115`) and `RehashPasswords bool` is at the wrong nesting level (spec 04-config says it belongs in `GoAuth`).

### 4.6 `account`

- This is the second-biggest gap after session. Better Auth's account linking is a security-sensitive surface (`disableImplicitLinking`, `requireLocalEmailVerified`, `trustedProviders`, `allowDifferentEmails`). Goauth only exposes `AllowUnlinkingAll`, so compat mode cannot express the other policies.

### 4.7 `verification`

- `storeIdentifier` controls whether tokens/OTPs are stored plain vs hashed (and per-type overrides) — relevant for the audit's `vulnerability-and-bug-audit.md`. Goauth's `VerificationOptions.DisableCleanup` alone is insufficient to match.

### 4.8 `rateLimit`, `telemetry`, `experimental`, `hooks`, `onAPIError`

- `rateLimit` is wired to `providers/sec-storage/redis` and `revocation_store.go` but the config only has `Storage string`. Better Auth lets you pass a `SecondaryStorage` adapter or `modelName`/`customRules`.
- `hooks`/`onAPIError`/`telemetry`/`experimental` have no representation in `AuthConfig` at all. They are the natural place for goauth's existing `plugin.HookRegistry` and error-format overrides.

## 5. What to keep as-is (goauth-only, intentional)

- `AuthConfig.GoAuth { Mode, TablePrefix, TableNames, Session SessionGoAuth }` — spec-approved extension point. Do not flatten.
- `EmailVerification.GoAuth { CodeSender, CodeGenerator, CodeExpiresIn }` — goauth's 6-digit code flow, no TS equivalent.
- `EmailAndPassword.GoAuth.SingleResetLink` — goauth-only constraint.
- `Advanced.GoAuth.OverrideHumaErrors`, `Advanced.Database.GenerateID`, `IPAddress` — keep, just align field names.
- Durations as `time.Duration` (not seconds) — keep, document conversion.
- `GoAuthOptions` runtime deps (`Conn`, `Repositories`, `Migrator`, `TxManager`, `SecondaryStorage`, `Plugins`) — keep on the setup struct, but add config-level mirrors (`Database`, `SecondaryStorage`) on `AuthConfig` that `SetupGoAuth` can consume as defaults.
- `*bool` for `Enabled`/`AutoSignIn`/`SendOnSignUp` to distinguish "unset" from `false` — keep.

## 6. Plan to make them match

Follow the "GoAuth sub-struct" rule for every new field that has no TS equivalent; mirror every TS field at its TS path and name.

### Phase 0 — Decide scope & compat policy

- [ ] Confirm this plan targets **wire/config parity** for `compat` mode (not a wholesale rename of every internal struct). `legacy` mode keeps current names.
- [ ] Decide deprecation window: keep old Go field names as aliases for one minor, `SetDefaults` maps + `slog.Warn` (pattern already used for `SessionConfig` → `Session.GoAuth.JWT` in spec migration table).
- [ ] Add `//go:generate` or a small `configtest` that diffs `AuthConfig` JSON keys against a checked-in `options.d.ts` snapshot so drift is caught in CI.

### Phase 1 — Top-level parity (highest leverage)

- [ ] Add `Secrets []SecretVersion` to `AuthConfig`:
  ```go
  type SecretVersion struct { Version int; Value string }
  // + helper: func (a *AuthConfig) EffectiveSecret() string
  // env: BETTER_AUTH_SECRETS="2:base64,1:base64" parsed in SetDefaults if Secrets empty
  ```
- [ ] Add `Database DatabaseConfig` to `AuthConfig` (mirrors TS `database` block):
  ```go
  type DatabaseConfig struct {
    Casing string // "camel"|"snake"
    DebugLogs bool
    Transaction bool
  }
  // Kysely instance passthrough not needed in Go; Conn/Repositories remain on GoAuthOptions.
  // SetDefaults maps Database.Casing -> models naming strategy if TablePrefix/TableNames not set.
  ```
- [ ] Add `SecondaryStorage SecondaryStorageConfig` to `AuthConfig` (typed adapter, not `string`):
  ```go
  // Keep GoAuthOptions.SecondaryStorage as runtime value; add AuthConfig.SecondaryStorage interface
  // so SetupGoAuth can do: if opts.AuthConfig.SecondaryStorage != nil && opts.SecondaryStorage == nil { opts.SecondaryStorage = opts.AuthConfig.SecondaryStorage }
  ```
- [ ] Add `SocialProviders SocialProvidersConfig` placeholder (even if empty map) so compat config that includes the key does not silently drop it. Backed by plugins today — doc that it is plugin-driven.
- [ ] Normalize `BaseURL` to support dynamic form:
  ```go
  type BaseURLConfig struct {
    AllowedHosts []string
    Fallback string
  }
  // AuthConfig.BaseURL stays string for simple case; add BaseURLConfig *BaseURLConfig
  // or change BaseURL to any with helper BaseURLString() string.
  // Recommended: type BaseURL struct { Value string; AllowedHosts []string; Fallback string } with UnmarshalText.
  ```

### Phase 2 — Session parity (largest behavioral gap)

- [ ] Add `CookieCache` to `Session`:
  ```go
  type CookieCache struct {
    Enabled  *bool              // nil = false (match TS default)
    MaxAge   time.Duration      // default 5m (5*60)
    Strategy CookieCacheStrategy // compact|jwt|jwe, default compact
    RefreshCache any            // bool | struct{ UpdateAge time.Duration }
    Version  any                // string | func(session,user) string
  }
  // Session.CookieCache *CookieCache (pointer so absent = disabled, matches TS optional)
  ```
  Reuse existing `CookieCacheStrategy` constants. Implement `strategy` dispatch in `providers/cookies` (compact = HMAC, jwt = HMAC-JWT, jwe = A256CBC-HS512).
- [ ] Consolidate JWT/session extra: move `SessionGoAuth` to `Session.GoAuth` per spec; keep `AuthConfig.GoAuth.Session` as alias that `SetDefaults` maps with deprecation warn, then remove in next minor.
- [ ] Add `ModelName`, `Fields`, `AdditionalFields` to `Session` / `User` / `Account` / `Verification` if custom schema is in scope; otherwise document as intentionally omitted with a `// not supported: use plugin additionalFields` comment.

### Phase 3 — `account` & `verification` parity

- [ ] Expand `AccountOptions` to mirror TS:
  ```go
  type AccountOptions struct {
    UpdateAccountOnSignIn *bool // default true
    AccountLinking AccountLinkingOptions
    EncryptOAuthTokens bool
    SkipStateCookieCheck bool
    StoreStateStrategy string // "database"|"cookie"
    StoreAccountCookie bool
  }
  type AccountLinkingOptions struct {
    Enabled *bool
    DisableImplicitLinking bool
    RequireLocalEmailVerified *bool // default true
    TrustedProviders []string       // or func(*http.Request) []string
    AllowDifferentEmails bool
    AllowUnlinkingAll bool         // already exists — keep
    UpdateUserInfoOnLink bool
  }
  ```
- [ ] Expand `VerificationOptions`:
  ```go
  type VerificationOptions struct {
    DisableCleanup bool
    StoreIdentifier any // StoreIdentifierOption | { Default, Overrides }
    StoreInDatabase bool
  }
  type StoreIdentifierOption string // "plain"|"hashed"
  // + struct { Default StoreIdentifierOption; Overrides map[string]StoreIdentifierOption }
  ```

### Phase 4 — `emailAndPassword` & `user` touch-ups

- [ ] Uncomment/implement `CustomSyntheticUser func(params SyntheticUserParams) map[string]any` on `EmailAndPassword` (remove `//` on line 115, add type).
- [ ] Move `RehashPasswords bool` into `EmailAndPassword.GoAuth` (leave deprecated alias at top level for one minor).
- [ ] `TrustedOrigins` — widen to support functional form:
  ```go
  type TrustedOriginsConfig struct {
    Origins []string
    Resolver func(*http.Request) []string // when set, called per-request, merged with Origins
  }
  // Or keep []string and add TrustedOriginsFunc func(*http.Request) []string alongside.
  ```
- [ ] `RateLimitOptions` — add `CustomRules` and `ModelName`, and allow `Storage` to be `SecondaryStorage`:
  ```go
  type RateLimitOptions struct {
    Enabled bool
    Window time.Duration
    Max int
    Storage any // string | SecondaryStorage
    CustomRules []RateLimitRule
    ModelName string
  }
  ```

### Phase 5 — `advanced`, `hooks`, `onAPIError`, `telemetry`, `experimental`

- [ ] `Advanced` — add `Cookies map[string]CookieAttributes`, `DefaultCookieAttributes *CookieAttributes`; alias `IPAddress.Headers` ↔ `ipAddressHeaders` and `DisableTracking` ↔ `disableIpTracking` via struct tags + doc; keep current fields as canonical Go names, accept TS names in JSON/koanf via tags.
- [ ] Add top-level `Hooks` and `OnAPIError` to `AuthConfig`:
  ```go
  type Hooks struct { Before, After func(...) } // mirror AuthMiddleware
  type OnAPIError struct { Throw *bool; OnError func(error, AuthContext); ErrorURL string }
  // Wire Hooks into plugin.HookRegistry; wire OnAPIError into types error handler.
  ```
- [ ] Add `Telemetry` and `Experimental`:
  ```go
  type Telemetry struct { Enabled, Debug bool }
  type Experimental struct { Joins bool }
  ```

### Phase 6 — Migration, defaults, validation, tests

- [ ] Extend `SetDefaults()` for every new field (defaults match TS `@default` annotations in options.d.ts — e.g. `session.cookieCache.maxAge = 5m`, `account.updateAccountOnSignIn = true`, `telemetry.enabled = false`).
- [ ] Extend `Validate()` — e.g. `cookieCache.strategy` must be one of `compact|jwt|jwe`; `storeStateStrategy` must be `database|cookie`; `secrets` versions must be unique and first is current.
- [ ] Add `config/config_compat_test.go` that constructs an `AuthConfig` from a JSON fixture shaped like a real `BetterAuthOptions` object and asserts round-trip parity (field presence + defaults). Include `secrets`, `cookieCache`, `accountLinking`, `verification.storeIdentifier` fixtures.
- [ ] Update `_docs/phase1/03-spec/04-config.md` and add a `MIGRATION.md` entry with the old→new table (extend the existing one with `secrets`, `CookieCache`, `Account.*`).
- [ ] Log deprecation warnings for moved fields (`RehashPasswords`, `Session.GoAuth` duplication) and keep aliases for one minor.

## 7. Suggested execution order

1. **Phase 1** (top-level `secrets`/`database`/`secondaryStorage` + `BaseURL` dynamic form) — unblocks env/rotation parity and multi-host deploys.
2. **Phase 2** (`session.cookieCache`) — unblocks stateless/JWE deployments and fixes the largest behavioral gap.
3. **Phase 3** (`account` + `verification`) — fixes security-relevant linking + token-storage semantics.
4. **Phase 4** (`emailAndPassword.customSyntheticUser`, `trustedOrigins` func, `rateLimit`) — small, low-risk.
5. **Phase 5** (`advanced.cookies`, `hooks`, `onAPIError`, `telemetry`, `experimental`) — mostly additive, no DB migration.
6. **Phase 6** (defaults/validation/tests/docs).

## 8. Out of scope (intentionally not matched)

- `database` Kysely/D1 dialect passthrough — Go uses GORM; expose only `casing/debugLogs/transaction` at config level, keep `*gorm.DB` injection on `GoAuthOptions`.
- `socialProviders` provider implementations — stay in plugins; config placeholder only.
- `plugins` array at `AuthConfig` level — duplicated by `GoAuthOptions.Plugins []plugin.Plugin`; do not duplicate.
- Internal cache sentinels (`cachedSecure`, `cachedDomainOnce`, `StoreSessionInDatabaseSet`) — keep, they are not part of TS contract.

## 9. Acceptance checklist

- [ ] `AuthConfig` JSON keys are a superset of `BetterAuthOptions` keys (checked by compat test).
- [ ] `SetupGoAuth` accepts a config that is a direct transliteration of a valid `betterAuth({ ... })` call in compat mode (modulo `time.Duration` vs seconds and Go func signatures).
- [ ] No existing `go test ./...` regression; new `config_compat_test.go` passes.
- [ ] Spec doc `04-config.md` and this plan agree on `GoAuth` sub-struct placement.

