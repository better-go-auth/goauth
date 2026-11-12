# 01 – Comparison: goauth vs better-go-auth vs better-auth

Legend: ✅ done / compatible · 🟡 partial or different shape · ❌ missing

## 1. Architecture

| Aspect | goauth | better-go-auth | better-auth (TS) |
|---|---|---|---|
| Module | `github.com/better-go-auth/goauth` (Go 1.26) | `github.com/better-go-auth/better-go-auth` (Go 1.25) | `better-auth` monorepo |
| Entry point | `goauth.SetupGoAuth(huma.API, GoAuthOptions)` | `bettergoauth.New(Options, AuthRepos)` + adapters | `betterAuth(options)` → `auth.handler` / `auth.api.*` |
| HTTP layer place| Huma only (registers on caller's API) | Huma (done), Gin/Fiber (stubs) | Framework-agnostic `Request → Response` (better-call) |
| ORM | GORM (sqlite/postgres) + repo interfaces | GORM, Bun (partial) | Adapters: kysely, drizzle, prisma, mongo, memory |
| Layering | handler → service → repo interfaces | adapter → service → repo interfaces | endpoint → `ctx.context.internalAdapter` → adapter |
| Server-side API | Services exposed via `IAuthServices` | Services | `auth.api.signInEmail({ body, headers })` |
| Observability | slog, OTel tracing middleware | OTel | logger, telemetry pkg |
| Tests | testcontainers (pg/redis) per module | e2e + unit + Bruno | vitest, adapter e2e |

## 2. Authentication model (the biggest difference)

| Aspect | goauth | better-go-auth | better-auth |
|---|---|---|---|
| Session credential | **JWT access token + JWT refresh token** | Opaque token (default) or HS256 JWT | **Opaque random token (32 chars)** |
| Transport | `Authorization: Bearer <access>` + `AccessToken`/`RefreshToken` cookies | Signed cookie `better-auth.session_token` | Signed cookie `better-auth.session_token`; Bearer via `bearer` plugin |
| Cookie signing | none | HMAC-SHA256, `value.base64sig` ✅ | HMAC-SHA256, `value.base64sig` (URL-encoded) |
| Refresh model | `POST /refresh` rotates tokens | Sliding (`UpdateAge`) ✅ | Sliding expiry (`updateAge`, default 1d) |
| Revocation | Blacklist in secondary storage + DB flag | delete row / secondary storage | delete row / secondary storage |
| Cookie cache (`session_data`) | ❌ (only enum types declared) | ✅ compact / jwt / jwe + chunking | ✅ compact (default) / jwt / jwe |
| Stateless mode (no DB) | ❌ (JWT is "stateless" but not compatible) | ✅ | ✅ |
| Secondary storage | ✅ interface (ctx-aware) – used for revocation only | ✅ used for sessions | ✅ sessions, rate-limit, verification |
| Fresh session (`freshAge`) | ❌ (field declared, unused) | ✅ | ✅ |
| remember me / `dont_remember` | ❌ | 🟡 | ✅ |
| Multi-session per device | ❌ | ❌ | ✅ plugin |

## 3. Core endpoints (default basePath `/api/auth`)

| better-auth endpoint | goauth today | better-go-auth |
|---|---|---|
| `POST /sign-up/email` | 🟡 `POST /signup` (firstName/lastName, code verification, GResp envelope) | ✅ |
| `POST /sign-in/email` | 🟡 `POST /login` (`info`, returns JWT pair) | ✅ |
| `POST /sign-out` | 🟡 `POST /logout` (needs refresh token) | ✅ |
| `GET /get-session` | ❌ | ✅ |
| `GET /list-sessions` | 🟡 `GET /session` | ✅ |
| `POST /revoke-session` | 🟡 `POST /session/{id}` | ✅ |
| `POST /revoke-sessions` / `/revoke-other-sessions` | ❌ | ✅ |
| `POST /update-session` | ❌ | ✅ |
| `POST /update-user` | 🟡 `PATCH /profile` | ✅ |
| `POST /change-password` | 🟡 `POST /profile/change_pwd` | ✅ |
| `POST /verify-password` | ❌ | ✅ |
| `POST /change-email` | 🟡 `POST /profile/change_email` + `/verify_change_email` (code) | ✅ |
| `POST /delete-user`, `GET /delete-user/callback` | ❌ (admin remove only) | 🟡 (no callback) |
| `POST /send-verification-email` | ❌ (code is sent on signup) | ✅ |
| `GET /verify-email?token=` | 🟡 `POST /verify` with 6-digit code | ✅ |
| `POST /request-password-reset` | 🟡 `POST /forgot_password` (code) | ✅ |
| `GET /reset-password/:token` | ❌ | ✅ |
| `POST /reset-password` | 🟡 `POST /reset_password` (code+info) | ✅ |
| `POST /sign-in/social`, `GET/POST /callback/:id` | ❌ | 🟡 (Google only, `GET /sign-in/{provider}`) |
| `POST /link-social`, `/unlink-account`, `GET /list-accounts` | ❌ | ✅ |
| `POST /account-info`, `/refresh-token`, `/get-access-token` | ❌ | ❌ |
| `GET /ok`, `GET /error` | ❌ | 🟡 (`/ok` only) |
| `GET /token`, `GET /jwks` (jwt plugin) | ❌ (has own JWT) | 🟡 stubbed |

## 4. Data model

| Table | goauth | better-go-auth | better-auth (default) |
|---|---|---|---|
| Table names | `auth_users`, `auth_sessions`, `auth_accounts`, `auth_verifications` | `users`, `sessions`, `accounts`, `verifications` | `user`, `session`, `account`, `verification` |
| Column naming | snake_case | snake_case | **camelCase** (`"emailVerified"`, `"userId"`), configurable per field |
| JSON naming | mixed (`created_at`, `firstName`, `org_id`, `last_seen`) | camelCase ✅ | camelCase |
| IDs | ULID / UUID | ULID | 32-char alphanumeric (pluggable `generateId`) |
| user.name | ❌ (`firstName`+`lastName`) | ✅ | required |
| user.image | 🟡 non-null string | ✅ | nullable |
| user.password | ⚠️ stored on user **and** account | account only ✅ | account only |
| user.role | 🟡 `"User"`/`"Admin"`, DB default `UNVERIFIED_PERSON` | ✅ `"user"` | admin plugin: `"user"` |
| user.banned/banReason/banExpires | ✅ | ✅ | admin plugin |
| session.token | ❌ (`SessionId` + `HashedToken`) | ✅ | required, unique |
| session.ipAddress/userAgent | ❌ | ✅ | ✅ |
| session.impersonatedBy | ❌ | ✅ | admin plugin |
| session.activeOrganizationId/activeTeamId | ❌ (on user as `org_id`) | 🟡 org only | org plugin |
| account | ✅ shape matches | ✅ | ✅ |
| verification | 🟡 extra `UserId` (not null), unique identifier, hashed value | 🟡 hashed value | identifier (indexed, not unique), plain value |
| rateLimit table | ❌ | ❌ | optional |

## 5. Crypto & security

| Aspect | goauth | better-go-auth | better-auth |
|---|---|---|---|
| Password hash | ⚠️ **bcrypt MinCost (4)**; argon2 helper unused | bcrypt cost 10 | **scrypt** `salt:hexkey` (N=16384,r=16,p=1,dkLen=64) |
| Pluggable hasher | 🟡 type declared, not wired | ✅ | ✅ `password.hash/verify` |
| Min/max password length | ❌ (declared only) | ✅ 8/128 | ✅ 8/128 |
| Error body | `GResp{body,status,code,message,error}` or Huma problem+json | `{code,message,statusCode}` | `{code, message}` + HTTP status |
| Trusted origins / origin check | ❌ | 🟡 config only | ✅ |
| CSRF (fetch metadata) | ❌ | ❌ | ✅ |
| callbackURL validation | ❌ | 🟡 | ✅ |
| Rate limiting | ❌ | 🟡 in-memory flag | ✅ memory / db / secondary storage, per-path rules |
| IP extraction / ipv6 subnet | ❌ | ❌ | ✅ |
| Email enumeration protection | 🟡 (timing only) | ✅ synthetic user | ✅ |
| OAuth token encryption | ❌ | ❌ | ✅ `encryptOAuthTokens` |

## 6. Extensibility

| Aspect | goauth | better-go-auth | better-auth |
|---|---|---|---|
| Plugin interface | `ID, Init, Migrator, Services, Routes` + optional `HookProvider` | same shape | `id, init, endpoints, schema, hooks{before,after}, middlewares, onRequest, onResponse, rateLimit, $ERROR_CODES, options` |
| Request hooks | ❌ | ❌ | ✅ `hooks.before/after` with matchers |
| Database hooks | 🟡 fixed lifecycle events (`BeforeUserCreate`, `SessionRevoked`, …) | ❌ | ✅ create/update/delete × before/after × model |
| additionalFields | ❌ | 🟡 synthetic user only | ✅ user/session/account/verification |
| disabledPaths | ❌ | ❌ | ✅ |
| Per-op RBAC | ✅ operation-ID + roles (goauth extension) | 🟡 middleware | via `access`/admin/org plugins |

## 7. Plugins

| Plugin | goauth | better-go-auth | better-auth |
|---|---|---|---|
| admin | 🟡 12/15 endpoints, paths mostly match | 🟡 service only | ✅ 15 endpoints |
| organization | 🟡 ~17/35 endpoints, paths match, roles differ, no teams/dynamic roles | 🟡 `/org/*` paths (not compatible) | ✅ 35 endpoints |
| email-otp | 🟡 goauth's code flows are effectively this | ❌ | ✅ |
| bearer / jwt | 🟡 custom JWT (incompatible) | 🟡 | ✅ |
| username, anonymous, phone-number, magic-link, two-factor, passkey, api-key, multi-session, one-time-token, generic-oauth, one-tap, device-authorization, oidc/oauth-provider, sso, scim, captcha, haveibeenpwned, last-login-method, siwe, stripe | ❌ | ❌ | ✅ |

## 8. Social providers

| | goauth | better-go-auth | better-auth |
|---|---|---|---|
| Providers | ❌ (enum only: google, github, twitter) | Google | 35 (apple, discord, facebook, github, gitlab, google, linkedin, microsoft, twitter, …) |

## 9. What each project is good at (what to take from where)

- **From better-go-auth, port:** `common/signedcookie`, `core/services/auth/cookie_cache.go`,
  `core/services/auth/verification_jwt.go`, `core/services/auth/secondary_storage.go`,
  `core/services/auth/OAuth.service.go`, `providers/oauth/*`, `core/dtos` (camelCase DTOs),
  `tests/e2e/cookie_cache_test.go` vectors.
- **Keep from goauth:** Huma integration & OpenAPI, repo interfaces + `TxManager`, hook registry
  (extend to full DB hooks), admin & org plugin services (rename/realign), testcontainers suites,
  `SecondaryStorage` with `context.Context`.
- **Take from better-auth:** the contract (paths, payloads, codes, defaults), plugin list, test cases
  (`packages/better-auth/src/**/*.test.ts` are an excellent behaviour checklist).
