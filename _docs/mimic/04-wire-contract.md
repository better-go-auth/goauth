# 04 – Wire contract (target behaviour)

Source of truth: `better-auth/packages/better-auth/src/api/routes/*.ts`,
`better-auth/packages/core/src/**`, and the exported spec in
`better-auth-schema/schema.json`. Items marked **(verify)** must be confirmed with a
captured response from the TS server before implementing (see 06).

Default base path: `/api/auth`. All bodies are JSON unless noted.

## 1. Core endpoints

| Method | Path | Request | 200 Response |
|---|---|---|---|
| POST | `/sign-up/email` | `{name, email, password, image?, callbackURL?, rememberMe?, ...additionalFields}` | `{token: string \| null, user: User}` |
| POST | `/sign-in/email` | `{email, password, callbackURL?, rememberMe? = true}` | `{redirect: bool, token: string, url?: string, user: User}` |
| POST | `/sign-in/social` | `{provider, callbackURL?, newUserCallbackURL?, errorCallbackURL?, disableRedirect?, idToken?{token,nonce?,accessToken?,refreshToken?}, scopes?, requestSignUp?, loginHint?}` | `{redirect: true, url}` or `{redirect: false, token, user}` |
| GET/POST | `/callback/:id` | query/form `code, state, error?, device_id?` | 302 to callbackURL (or errorURL `?error=`) |
| POST | `/sign-out` | – | `{success: true}` |
| GET (POST only with `deferSessionRefresh`) | `/get-session` | query `disableCookieCache?, disableRefresh?` | `{session: Session, user: User}` or `null`; `+needsRefresh` on GET when deferring; `Cache-Control: no-store` |
| GET | `/list-sessions` | – (requires fresh session) | `Session[]` (raw array) **(verify)** |
| POST | `/revoke-session` | `{token}` | `{status: true}` |
| POST | `/revoke-sessions` | – | `{status: true}` |
| POST | `/revoke-other-sessions` | – | `{status: true}` |
| POST | `/update-session` | `{...session additionalFields}` | `{session}` **(verify)** |
| POST | `/update-user` | `{name?, image?, ...additionalFields}` (email forbidden) | `{status: true}` |
| POST | `/change-password` | `{newPassword, currentPassword, revokeOtherSessions?}` | `{token: string \| null, user}` |
| POST | `/verify-password` | `{password}` | `{status: true}` |
| POST | `/change-email` | `{newEmail, callbackURL?}` | `{status: true}` |
| POST | `/delete-user` | `{callbackURL?, password?, token?}` | `{success: true, message: "User deleted" \| "Verification email sent"}` |
| GET | `/delete-user/callback` | query `token, callbackURL?` | redirect or `{success: true, message}` |
| POST | `/send-verification-email` | `{email, callbackURL?}` | `{status: true}` |
| GET | `/verify-email` | query `token, callbackURL?` | redirect or `{status: true, user?}` **(verify)** |
| POST | `/request-password-reset` | `{email, redirectTo?}` | `{status: true, message}` (always) |
| GET | `/reset-password/:token` | query `callbackURL` | 302 `callbackURL?token=…` or `?error=INVALID_TOKEN` |
| POST | `/reset-password` | `{newPassword, token}` | `{status: true}` |
| POST | `/link-social` | `{provider, callbackURL?, scopes?, idToken?, disableRedirect?}` | `{url, redirect: bool}` |
| POST | `/unlink-account` | `{providerId, accountId?}` | `{status: true}` |
| GET | `/list-accounts` | – | `[{id, providerId, accountId, userId, scopes: string[], createdAt, updatedAt}]` |
| POST | `/account-info` | `{accountId?}` | `{user: {id,name,email,image,emailVerified}, data: object}` **(verify)** |
| POST | `/refresh-token` | `{providerId, accountId?, userId?}` | `{accessToken, refreshToken, accessTokenExpiresAt, ...}` |
| POST | `/get-access-token` | `{providerId, accountId?, userId?}` | `{accessToken, accessTokenExpiresAt, scopes, idToken}` |
| GET | `/ok` | – | `{ok: true}` |
| GET | `/error` | query `error?` | HTML page |

Server-only (not HTTP): `setPassword`, `createUser` (admin), `signInEmail` with `asResponse`.

### Common objects

```jsonc
// User
{"id":"…","name":"…","email":"…","emailVerified":false,"image":null,
 "createdAt":"2026-01-01T00:00:00.000Z","updatedAt":"…" /* + returned additionalFields / plugin fields */}
// Session
{"id":"…","userId":"…","token":"…","expiresAt":"…","ipAddress":"…","userAgent":"…",
 "createdAt":"…","updatedAt":"…" /* + plugin fields e.g. activeOrganizationId, impersonatedBy */}
```

Dates are ISO-8601 strings with milliseconds (`time.RFC3339Nano` trimmed to ms, UTC, `Z`).

## 2. Database schema (better-auth default, naming = `NamingBetterAuth`)

| Table | Columns |
|---|---|
| `user` | `id` text pk, `name` text not null, `email` text unique not null, `emailVerified` bool not null, `image` text, `createdAt` timestamp, `updatedAt` timestamp |
| `session` | `id`, `expiresAt`, `token` unique, `createdAt`, `updatedAt`, `ipAddress`, `userAgent`, `userId` fk→user (cascade) |
| `account` | `id`, `accountId`, `providerId`, `userId` fk, `accessToken`, `refreshToken`, `idToken`, `accessTokenExpiresAt`, `refreshTokenExpiresAt`, `scope`, `password`, `createdAt`, `updatedAt` |
| `verification` | `id`, `identifier` (indexed), `value`, `expiresAt`, `createdAt`, `updatedAt` |
| `rateLimit` (opt.) | `id`, `key`, `count`, `lastRequest` bigint |

Postgres columns are camelCase and must be quoted. Regenerate this table from
`npx @better-auth/cli generate` in `better-auth-schema/` when better-auth is upgraded.

Identifier conventions in `verification`:

| Flow | identifier | value |
|---|---|---|
| Password reset | `reset-password:<token>` | userId |
| Delete account | `delete-account-<token>` **(verify)** | userId |
| OAuth state (db strategy) | `<state>` | JSON state data |
| email-otp | `<type>-otp-<email>` | `<otp>:<attempts>` |
| magic-link | `<token>` | JSON `{email,name,attempt}` |

## 3. Cookies

| Cookie | Value | Attributes |
|---|---|---|
| `{prefix}.session_token` | `encodeURIComponent(token + "." + base64std(HMAC-SHA256(secret, token)))` | HttpOnly, SameSite=Lax, Path=/, Max-Age=expiresIn (omitted when rememberMe=false), Secure on https |
| `{prefix}.session_data` | cookie-cache payload (compact/jwt/jwe), chunked `.0..n` when > ~4 KB | same, Max-Age=cookieCache.maxAge |
| `{prefix}.dont_remember` | signed `"true"` | session cookie |
| `{prefix}.state` / `{prefix}.pk_code_verifier` | OAuth cookie strategy | Max-Age=600 **(verify)** |
| `{prefix}.admin_session` | signed `"<adminSessionToken>:<dontRemember>"` (admin impersonation) **(verify)** | |

`{prefix}` = `better-auth` by default. With secure cookies the name is prefixed with `__Secure-`.

Headers: bearer plugin → response `set-auth-token`; jwt plugin → `set-auth-jwt`.

## 4. Session semantics

- token: 32 chars `[a-zA-Z0-9]`; `expiresIn` 7d; `updateAge` 1d; `freshAge` 1d.
- Refresh when `now >= expiresAt - expiresIn + updateAge`; new `expiresAt = now + expiresIn`; cookie re-set.
- `rememberMe=false`: session lasts 1 day, never refreshed, `dont_remember` cookie set.
- Secondary storage keys: `<token>` → `{"session":…,"user":…}`;
  `active-sessions-<userId>` → `[{"token":"…","expiresAt":<ms>}]`.
- Cookie cache: default strategy `compact`, `maxAge` 300 s; `refreshCache.updateAge` = 20 % of maxAge.

## 5. Crypto

| Item | Spec |
|---|---|
| Password hash | scrypt N=16384, r=16, p=1, dkLen=64; salt = 16 random bytes → hex string used **as the salt bytes**; password NFKC-normalised; stored `"<saltHex>:<keyHex>"` **(verify with TS vector)** |
| Cookie signature | HMAC-SHA256(secret), standard base64 with padding |
| Email verification token | JWT HS256 signed with `secret`, payload `{email, updateTo?, requestType?}`, `exp = now + emailVerification.expiresIn` (default 3600 s) |
| Symmetric encryption | XChaCha20-Poly1305, key `SHA-256(secret)`, random 24-byte nonce prepended, hex |
| JWE cookie cache | `dir` + `A256CBC-HS512`, key = HKDF-SHA256(secret, salt/info as in TS) – port from better-go-auth |
| Password length | min 8, max 128 |

## 6. Errors

Body: `{"code": "<CODE>", "message": "<text>"}`. Status per endpoint (usually 400/401/403/404/422).

Core codes (`packages/core/src/error/codes.ts`):
`USER_NOT_FOUND, FAILED_TO_CREATE_USER, FAILED_TO_CREATE_SESSION, FAILED_TO_UPDATE_USER,
FAILED_TO_GET_SESSION, INVALID_PASSWORD, INVALID_EMAIL, INVALID_EMAIL_OR_PASSWORD, INVALID_USER,
SOCIAL_ACCOUNT_ALREADY_LINKED, PROVIDER_NOT_FOUND, INVALID_TOKEN, TOKEN_EXPIRED,
ID_TOKEN_NOT_SUPPORTED, FAILED_TO_GET_USER_INFO, USER_EMAIL_NOT_FOUND, EMAIL_NOT_VERIFIED,
PASSWORD_TOO_SHORT, PASSWORD_TOO_LONG, USER_ALREADY_EXISTS, USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL,
EMAIL_CAN_NOT_BE_UPDATED, CHANGE_EMAIL_DISABLED, CREDENTIAL_ACCOUNT_NOT_FOUND, SESSION_EXPIRED,
FAILED_TO_UNLINK_LAST_ACCOUNT, ACCOUNT_NOT_FOUND, USER_ALREADY_HAS_PASSWORD,
CROSS_SITE_NAVIGATION_LOGIN_BLOCKED, VERIFICATION_EMAIL_NOT_ENABLED, EMAIL_ALREADY_VERIFIED,
EMAIL_MISMATCH, SESSION_NOT_FRESH, LINKED_ACCOUNT_ALREADY_EXISTS, INVALID_ORIGIN,
INVALID_CALLBACK_URL, INVALID_REDIRECT_URL, INVALID_ERROR_CALLBACK_URL,
INVALID_NEW_USER_CALLBACK_URL, MISSING_OR_NULL_ORIGIN, CALLBACK_URL_REQUIRED,
FAILED_TO_CREATE_VERIFICATION, FIELD_NOT_ALLOWED, ASYNC_VALIDATION_NOT_SUPPORTED,
VALIDATION_ERROR, MISSING_FIELD, METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED,
BODY_MUST_BE_AN_OBJECT, PASSWORD_ALREADY_SET`.

Generate the Go catalogue from the TS file (script in 06) so messages stay identical.

## 7. Security defaults

| Item | Default |
|---|---|
| Trusted origins | `BaseURL` origin + `TrustedOrigins` (wildcards `*.x.com`, custom schemes) |
| Origin check | non-GET requests with cookies; disable via `Advanced.DisableOriginCheck` |
| Rate limit | enabled in production; `window=10s, max=100`; `/sign-in/*`, `/sign-up/*`, `/change-password`, `/change-email` → `window=10s, max=3`; 429 + `X-Retry-After` |
| IP header | `x-forwarded-for` (configurable), IPv6 grouped by /64 |

## 8. Options mapping (better-auth → goauth)

| better-auth | goauth (target) |
|---|---|
| `appName`, `baseURL`, `basePath`, `secret`, `trustedOrigins` | `AuthConfig.AppName/BaseURL/BasePath/Secret/TrustedOrigins` |
| `database` | `GoAuthOptions.Conn` / `Repositories` + `Schema` |
| `secondaryStorage` | `GoAuthOptions.SecondaryStorage` |
| `emailAndPassword.*` | `AuthConfig.EmailAndPassword` |
| `emailVerification.*` | `AuthConfig.EmailVerification` |
| `socialProviders` | `AuthConfig.SocialProviders []oauth.Provider` |
| `user.{modelName,fields,additionalFields,changeEmail,deleteUser}` | `AuthConfig.User` |
| `session.{expiresIn,updateAge,freshAge,cookieCache,…}` | `AuthConfig.Session` (replaces `SessionConfig` JWT vars in Compat) |
| `account.{accountLinking,encryptOAuthTokens,storeStateStrategy}` | `AuthConfig.Account` |
| `verification.*` | `AuthConfig.Verification` |
| `rateLimit.*` | `AuthConfig.RateLimit` |
| `advanced.*` | `AuthConfig.Advanced` |
| `hooks`, `databaseHooks` | `AuthConfig.Hooks`, `AuthConfig.DatabaseHooks` |
| `plugins` | `GoAuthOptions.Plugins` |
| `disabledPaths`, `onAPIError`, `logger` | `AuthConfig.DisabledPaths`, `OnAPIError`, `Logger *slog.Logger` |
