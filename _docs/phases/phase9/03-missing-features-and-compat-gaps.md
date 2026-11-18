# 03 – Missing features and compatibility gaps

What better-auth v1.6.16 has that goauth does not, and the differences that stop goauth from being a drop-in
replacement (same database, same client, same responses). Checked against the better-auth sources in
`src/tests/compat/client/node_modules/better-auth/dist` on 2026-11-17.

Legend: **Blocker** = breaks a shared database or an official client; **Gap** = feature missing;
**Diff** = works, but responds differently.

---

## 1. Compatibility blockers (fix before claiming "full compatibility")

| # | Area | Problem | Fix |
|---|---|---|---|
| B1 | Column naming | goauth columns are snake_case (`email_verified`); better-auth's default Kysely/Drizzle/Prisma schemas are camelCase (`emailVerified`). A default TypeScript server cannot share the database unless it maps every field. Planned as "step 10" in phase 1 (`03-spec/03-schema.md`) but never done. | `GoAuth.ColumnCase = "camel"` in the naming strategy, plus per-field `Fields` mapping ([02-dynamic-columns-plan.md](02-dynamic-columns-plan.md) §4.4). |
| B2 | `additionalFields` / plugin schema | Not supported; apps with extra user/session fields can't use goauth, and a TypeScript server with `additionalFields` writes columns goauth ignores. | [02-dynamic-columns-plan.md](02-dynamic-columns-plan.md). |
| B3 | Account uniqueness | Extra unique index `(user_id, provider_id)`; better-auth allows several accounts per provider. | **Fixed in 9.1**: index dropped by migration (see [01](01-robustness-and-parity-improvements.md) §1.6). |
| B4 | Social providers placement | better-auth configures `socialProviders` in core and exposes `/sign-in/social`, `/callback/:id`, `/link-social`, `/get-access-token`, `/refresh-token`, `/account-info` without a plugin. goauth requires the `social` plugin. Same endpoints, but configuration and `GetPlugin` lookups differ. | **Fixed (missing-tasks 3.7)**: `AuthConfig.SocialProviders` + `Account.*` install the social plugin; generic-oauth providers are social providers. |
| B5 | Rate limiting defaults | better-auth enables a global limiter in production (100 req/10 s, sign-in/up 3/10 s); goauth has none on core routes. Clients relying on 429 behaviour (and abuse protection) differ. | **Fixed in stage 3.1**: global limiter ([01](01-robustness-and-parity-improvements.md) §2.5, `src/providers/ratelimit`). |
| B6 | `rateLimit` table / `storage: "database"` | Not supported. | Add `rateLimit` model when `RateLimit.Storage = "database"`. |
| B7 | Secret rotation | better-auth 1.6 supports `secrets` (versioned keys, `$ba$<v>$` envelopes) for cookies and encrypted data. `authcrypto.SecretKeys` exists but `AuthConfig` still has a single `Secret`, and new plugins encrypt with `Secret` only. | **Fixed (missing-tasks 3.5)**: `AuthConfig.Secrets`, `authcrypto.SecretKeys` for every envelope, JWE and cookie signature. |
| B8 | Organization endpoints | Role routes and `/has-permission` **added in 9.4**. Still missing: `/get-active-member`, `/get-active-member-role`, `/list-user-teams`. goauth also has extra non-better-auth paths (`/organization/team/*`, `/admin/organization/*`). | **Fixed (missing-tasks 3.8)**: routes added, every org route re-audited; extras documented in the org example. |
| B9 | Update-user unknown keys | goauth rejects unknown fields (`FIELD_NOT_ALLOWED`); better-auth ignores them, and rejects `phoneNumber` with `PHONE_NUMBER_CANNOT_BE_UPDATED`. | Compat mode drops unknown keys; plugins can contribute "forbidden update" fields with their own error. |
| B10 | Default-false plugin fields | `twoFactorEnabled:false` and `phoneNumberVerified` (when no phone) are omitted from user JSON; better-auth returns them (`false`/`null`) when the plugin is installed. TypeScript code doing `user.twoFactorEnabled === false` behaves differently. | Output driven by the schema registry: fields of installed plugins always present. |

---

## 2. Missing core features

| Feature | better-auth | goauth today | Notes |
|---|---|---|---|
| `databaseHooks` | create/update/delete before/after for user, session, account, verification | Fixed set of hook methods | [01](01-robustness-and-parity-improvements.md) §2.2 |
| `hooks.before/after` (endpoint middleware) | yes, plus plugin `hooks` | only `OnAfterSignIn` | [01](01-robustness-and-parity-improvements.md) §2.3 |
| `onAPIError` (`errorURL`, `onError`, `throw`) | yes | hard-coded `<base>/error` | |
| `baseURL` with `allowedHosts` / dynamic base URL | yes | static string | Needed for multi-domain / preview deployments |
| `trustedOrigins` as a function of the request | yes | static list | |
| `advanced.cookies` / `defaultCookieAttributes` | per-cookie name/attribute overrides | prefix + secure + cross-subdomain only | |
| `advanced.backgroundTasks` | async senders | none | |
| `advanced.database.generateId: false / "uuid" / "serial"` | yes | custom func only | numeric IDs matter for some shared DBs |
| `verification.storeIdentifier` (plain/hashed) | yes | plain only | hashing tokens at rest |
| `account.storeAccountCookie` | yes | no | social `/account-info` without `accountId` |
| `session.additionalFields`, `user.additionalFields`, `account.additionalFields` | yes | no | [02](02-dynamic-columns-plan.md) |
| `modelName` / `fields` per model | yes | `TablePrefix` + `TableNames` only | [02](02-dynamic-columns-plan.md) §4.4 |
| Logger options (`logger.level`, `disabled`, custom) | yes | `slog` defaults | |
| `telemetry` | yes | no | intentionally out of scope |
| CLI `generate` / `migrate` | yes | AutoMigrate at startup | add a `goauth migrate --dry-run` command printing SQL |
| OpenAPI document of auth routes | `open-api` plugin | Huma generates one already | expose it at `/api/auth/reference` like the plugin, using Scalar |
| Expired verification cleanup | on read | on read (since 9.1) | [01](01-robustness-and-parity-improvements.md) §1.2 |

---

## 3. Plugins: status

### Implemented in goauth
admin, organization (partial, see B8), bearer, jwt, email-otp, two-factor, magic-link, phone-number, passkey,
social (core in better-auth), username, anonymous, multi-session, one-time-token, generic-oauth and access
(createAccessControl, used by admin and organization; phase 9.4), plus goauth-only access-token.

### Missing better-auth plugins (built into the `better-auth` package)

| Plugin | Endpoints | Effort | Value |
|---|---|---|---|
| **custom-session** | overrides `/get-session` response via a callback | S | Medium |
| **last-login-method** | `lastLoginMethod` cookie / field updated on every sign-in | S | Low |
| **haveibeenpwned** | k-anonymity password check on sign-up / change / reset | S | Medium (security) |
| **captcha** | before-hook verifying Turnstile / reCAPTCHA / hCaptcha / CaptchaFox on configured paths | S | Medium |
| **one-tap** | `/one-tap/callback` (Google One Tap id_token) | S (reuse social google `VerifyIDToken`) | Low |
| **oauth-proxy** | `/oauth-proxy-callback` for preview deployments | S | Low |
| **siwe** | `/siwe/nonce`, `/siwe/verify` (Sign-In with Ethereum, EIP-4361) | M | Niche |
| **device-authorization** | `/device/code`, `/device/token`, `/device`, `/device/approve`, `/device/deny` (RFC 8628) | M | Medium (CLIs, TVs) |
| **oidc-provider** | `/.well-known/openid-configuration`, `/oauth2/authorize`, `/consent`, `/token`, `/userinfo`, `/register`, `/client/:id`, `/endsession` | L | High for "be an IdP" use cases (pairs with jwt) |
| **mcp** | OAuth authorization server for MCP clients (`/mcp/*`, `/.well-known/oauth-*`) | M (on top of oidc-provider) | Medium |
| **open-api** | `/open-api/generate-schema` + reference page | S | Low |

### Published as separate packages
**@better-auth/api-key** (API keys with rate limits, permissions, `x-api-key` session) and
**@better-auth/scim** (SCIM 2.0 provisioning) are the most requested ones for a Go backend; SSO (SAML/OIDC per
organization) and Stripe exist in the ecosystem too. Recommended order: api-key → SSO → SCIM.

---

## 4. Response / behaviour differences in implemented features

Collected from the plugin implementation reports; each is small but visible to a client:

| Feature | Difference |
|---|---|
| Phone number | Sign-in route also rate-limited with the `/sign-in` special rule (better-auth applies it globally). Missing `GetTempEmail` falls back to `<phone>@phone.invalid`. |
| Passkey | Anonymous request with an invalid body → 401 before validation; "origin missing" error uses code `BAD_REQUEST`. |
| Two-factor | Expired `2fa-*` verification row treated as an invalid cookie (better-auth trusts cookie max-age only). |
| Social | No account cookie; generic provider prefers id_token claims; empty provider name/image never overwrite profile on link. |
| Email OTP | `request-email-change` uses a normal session, better-auth requires a *fresh* session (`sensitiveSessionMiddleware`). |
| Errors | ~~`FAILED_TO_CREATE_USER` status~~ fixed in 9.1: core sign-up 422, admin/email-otp/phone-number 500, as in better-auth. |

---

## 5. Suggested roadmap

| Phase | Content | Why first |
|---|---|---|
| 9.1 | Robustness fixes [01](01-robustness-and-parity-improvements.md) §1 (cleanup, atomic attempts, admin delete, origin checks, account index) | security and data integrity |
| 9.2 | Schema registry + additionalFields steps 1–6, camelCase option (B1, B2, B10) | biggest compatibility blocker |
| 9.3 | Global rate limiter, `databaseHooks`, endpoint hooks, `onAPIError`, secrets rotation (B5–B7) | config parity |
| 9.4 | ~~access, org role routes, username, anonymous, generic-oauth, one-time-token, multi-session~~ done; remaining B8 routes | most-used missing plugins |
| 9.5 | api-key, captcha, haveibeenpwned, custom-session, last-login-method | cheap wins |
| 9.6 | oidc-provider → mcp, device-authorization, SSO | larger, IdP-side features |
| ongoing | Live parity suite against the TypeScript reference server + shared-database tests ([01](01-robustness-and-parity-improvements.md) §4) | prevents regressions |
