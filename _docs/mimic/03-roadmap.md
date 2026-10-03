# 03 – Roadmap (easy → hard)

Each step lists **what**, **where** (files/packages to touch or create),
**port from** (better-go-auth source to reuse) and **done when** (acceptance test).
Steps inside a phase are ordered by effort; phases are ordered by dependency.
Gap IDs (A1, B2, …) refer to [02-gap-analysis.md](02-gap-analysis.md).

Proposed new package layout (introduced gradually, nothing is moved until needed):

```
goauth/
  compat/            # wire-format helpers: errors, cookies, responses, ids
  src/crypto/        # scrypt, hmac, symmetric encryption, jwt helpers
  src/session/       # SessionManager (opaque token, refresh, cookie cache)
  src/security/      # origin check, csrf, rate limiter, ip
  src/app/core/ba/   # better-auth compatible core endpoints (Compat mode)
  src/plugins/<id>/  # one folder per plugin, id == better-auth plugin id
```

---

## Phase 0 – Groundwork (S, no behaviour change) ✅ done

**0.1 Clean plugin package** (G4)
- Delete the dead duplicate types in `src/plugins/plugin.go` (`InitContex`, `Plugi`, `RouteDescripto`).
- Done when: `go build ./... && go test ./src/plugins/...` pass.

**0.2 Add top-level options** (B3)
- Add to `config.AuthConfig`: `AppName`, `BaseURL`, `Secret`, `TrustedOrigins []string`,
  `Mode` (`ModeLegacy` default for now, `ModeCompat`), `Advanced{CookiePrefix, UseSecureCookies,
  CrossSubDomainCookies{Enabled,Domain}, DisableCSRFCheck, DisableOriginCheck, GenerateID func() string,
  IPAddress{Headers, DisableTracking, IPv6Subnet}}`, `DisabledPaths []string`.
- Wire existing `EmailAndPassword` config into `GoAuthOptions` (it's defined but not embedded).
- Defaults: `AppName="Better Auth"`, `CookiePrefix="better-auth"`, `Secret` from `BETTER_AUTH_SECRET`
  env, fall back to `SessionConfig.AccessSecret` in Legacy mode.
- `Validate()`: Compat mode requires `Secret` (≥ 32 chars warning) and `BaseURL`.
- Done when: unit test for `SetDefaults/Validate` matrix.

**0.3 Error code catalogue** (A2)
- Create `compat/errors.go` with all better-auth `BASE_ERROR_CODES` (see 04 §6) as
  `var ErrInvalidEmailOrPassword = compat.Err(401, "INVALID_EMAIL_OR_PASSWORD", "Invalid email or password")`.
- Plugins register their own codes via `compat.Register(code, msg)`.
- Done when: table test asserts every TS code exists with identical message text
  (generate list from `better-auth/packages/core/src/error/codes.ts`).

**0.4 Compat test harness**
- Create `src/tests/compat/` with helpers: start goauth on `httptest.Server`, cookie jar,
  `assertJSONShape(t, got, golden)`. Golden files under `src/tests/compat/golden/*.json`.
- See [06-compat-testing.md](06-compat-testing.md).

---

## Phase 1 – Wire primitives (S each, pure functions + unit tests)

**1.1 Fix password hashing now** (D1)
- Replace `bcrypt.MinCost` with `bcrypt.DefaultCost` in `src/providers/hasher/hasher.go` immediately.

**1.2 scrypt hasher compatible with better-auth** (D2, D3)
- `src/crypto/password.go`: `Hash(pw) -> "<saltHex>:<keyHex>"`, `Verify(hash, pw)`;
  NFKC-normalise password (`golang.org/x/text/unicode/norm`), 16-byte random salt hex-encoded,
  `scrypt.Key(pw, []byte(saltHex), 16384, 16, 1, 64)`, constant-time compare.
- `PasswordHasher{Hash, Verify}` option in `EmailAndPassword.Password`.
- Legacy verify chain: if hash starts with `$2` → bcrypt, `$argon2` → argon2; on success
  re-hash with scrypt and update `account.password` (transparent upgrade).
- Done when: verifies a hash produced by the TS server (`better-auth-schema`) and TS verifies Go's.

**1.3 Signed cookies** (B2)
- `compat/signedcookie` ← port `better-go-auth/common/signedcookie` (HMAC-SHA256, std padded base64,
  `value.signature`, URL-encode on write/decode on read).
- Done when: round-trip test + parse a cookie captured from the TS server.

**1.4 IDs and tokens** (C8)
- `compat/id.go`: `GenerateID()` 32-char `[a-zA-Z0-9]` using `crypto/rand`;
  `Advanced.GenerateID` override; keep ULID as an option (`compat.ULID`).
- Session token generator = same 32-char alphabet.

**1.5 Error responses** (A2)
- Override `huma.NewError` / `huma.NewErrorWithContext` (extend `src/common/types/override-huma.go`)
  to emit `{"code": "...", "message": "..."}` for `*compat.APIError` and map validation errors to
  `VALIDATION_ERROR` (400).
- Done when: `POST /sign-in/email` with bad body returns 400 `{code:"VALIDATION_ERROR",…}`.

**1.6 Raw JSON responses** (A1)
- Compat handlers return `*struct{ Body T; SetCookie []http.Cookie \`header:"Set-Cookie"\` }`
  (plain Huma output) – **no GResp**. Keep GResp for Legacy routes only.

**1.7 Cookie manager** (B2, B7)
- `compat/cookies.go`: names `{prefix}.session_token`, `{prefix}.session_data`, `{prefix}.dont_remember`,
  `__Secure-` prefix when `BaseURL` is https or `UseSecureCookies`; attributes
  `HttpOnly; SameSite=Lax; Path=/; Max-Age=<expiresIn>`; `Domain` when cross-subdomain.
- `SetSessionCookie(w, token, rememberMe)`, `DeleteSessionCookies(w)`.

**1.8 `/ok` and `/error`** (A7)
- `GET /ok` → `{"ok":true}`; `GET /error` → simple HTML or JSON by `Accept`.

**1.9 Crypto helpers** (D5)
- `src/crypto/symmetric.go`: XChaCha20-Poly1305 with key = `SHA-256(secret)`, managed nonce
  prepended, hex output – matching `better-auth/packages/better-auth/src/crypto/index.ts`
  (also handle its versioned/secret-rotation payload format). Needed for OAuth tokens & jwks.
- `src/crypto/jwt.go`: HS256 sign/verify with `secret` (port `verification_jwt.go`).

---

## Phase 2 – Schema alignment (M)

**2.1 Compat DTOs separate from GORM models** (A6)
- `compat/dto`: `User{id,name,email,emailVerified,image,createdAt,updatedAt,+additional}`,
  `Session{id,userId,token,expiresAt,ipAddress,userAgent,createdAt,updatedAt,+additional}`,
  `Account` (no password/token fields exposed in list), port from `better-go-auth/core/dtos`.
- All compat endpoints serialise these, never GORM structs.

**2.2 User model** (C1, C2, C4, C6)
- Add `Name string` (not null), `Image *string`; keep `FirstName/LastName` as optional extension
  columns; on create derive `Name = strings.TrimSpace(first+" "+last)` when missing.
- Remove `Password` from user (migration copies into `account.password` with `providerId="credential"`).
- Role: lowercase values `user`/`admin`; DB default `user`; support comma-separated multi-role.
- Move `Active`, `AccountStatus`, `ActiveOrgId`, `LastSeen`, `Bio`, … behind
  `user.AdditionalFields` (Phase 6) – until then keep columns but omit from compat DTO.

**2.3 Session model** (B4)
- Add `Token` (unique), `IPAddress *string`, `UserAgent *string`, `ImpersonatedBy *string`,
  `ActiveOrganizationID *string`, `ActiveTeamID *string`. Make `SessionId`, `HashedToken`, `Role`
  nullable (Legacy only).

**2.4 Verification model** (C5)
- `UserId` nullable, `Identifier` indexed (not unique), `Value` stored as-is (better-auth semantics).
  Legacy code-based flows keep hashing inside their own value format.

**2.5 Naming strategy** (C3)
- `Schema` option: `Naming: NamingGoauth` (current `auth_*`, snake_case) |
  `NamingBetterAuth` (`user`, `session`, `account`, `verification`, camelCase columns) |
  custom `ModelName map[string]string` + `Fields map[string]map[string]string`.
- Implement with a GORM `schema.Namer` + per-model `TableName()` reading config.
- Done when: goauth migrates an empty Postgres, then the TS server (`better-auth-schema`)
  runs `npx @better-auth/cli migrate` against it and reports **no changes**.

**2.6 Data migration for existing goauth DBs** (C9)
- `src/models/migration/v2/`: idempotent SQL/GORM migration: add columns, backfill `name`,
  move passwords to account, lowercase roles, generate `token` for active sessions (or revoke all).
- Document in `goauth/_docs/mimic/` follow-up `MIGRATING.md` when implemented.

---

## Phase 3 – Session engine (L)

**3.1 SessionManager** (B1, B5)
- `src/session/manager.go`:
  `Create(ctx, userID, r, opts{RememberMe, Override})`, `Get(ctx, token)`, `Refresh`, `Delete`,
  `DeleteUserSessions`, `List(userID)`.
- Defaults: `ExpiresIn=7d`, `UpdateAge=1d`, `FreshAge=1d`; refresh when
  `expiresAt - expiresIn + updateAge <= now` → set `expiresAt=now+expiresIn` and re-set cookie.
- `RememberMe=false` → cookie without Max-Age + `dont_remember` cookie, session `expiresIn=1d`,
  never refreshed.
- Honour `DisableSessionRefresh`, `DeferSessionRefresh` (refresh only on POST).
- Fire hook `BeforeSessionCreate` (existing registry) until Phase 6 DB hooks land.

**3.2 Session resolution middleware** (B9)
- `src/session/middleware.go`: read signed cookie → verify HMAC → `Get(token)`; check expiry;
  put `*compat.SessionWithUser` in context; `RequireSession()` / `OptionalSession()` /
  `RequireFreshSession()` Huma middlewares returning `401 UNAUTHORIZED` / `403 SESSION_NOT_FRESH`.
- Legacy mode keeps `AuthMiddleware.Authenticate()` (JWT).

**3.3 Secondary storage sessions** (B8)
- Port `better-go-auth/core/services/auth/secondary_storage.go`. Key layout identical to
  better-auth: key `<token>` → JSON `{session,user}` TTL = expiresAt; key `active-sessions-<userId>`
  → JSON array `[{token, expiresAt}]`.
- `StoreSessionInDatabase`, `PreserveSessionInDatabase` honoured.
- Adapt existing `SecondaryStorage` (ctx-aware) – values stored as **strings** (JSON) for
  cross-language Redis sharing.

**3.4 Session cleanup** – `GoAuth.StartSessionCleanup(ctx, interval)` deletes expired rows.

**3.5 `GET|POST /get-session`** (A5)
- Query `disableCookieCache`, `disableRefresh`; returns `{session,user}` or JSON `null` (200).

---

## Phase 4 – Core email/password endpoints (M each)

Implement in `src/app/core/ba/` (Compat mode). Each returns shapes from 04 §1.

| Step | Endpoint(s) | Notes |
|---|---|---|
| 4.1 | `POST /sign-up/email` | `name,email,password,image?,callbackURL?,rememberMe?` + additional fields; min/max length; `DisableSignUp`; `RequireEmailVerification` → `{token:null,user}`; enumeration-safe when user exists (synthetic user + `OnExistingUserSignUp`) |
| 4.2 | `POST /sign-in/email` | `email,password,callbackURL?,rememberMe?`; `EMAIL_NOT_VERIFIED` (403) + optional resend; ban check (admin plugin hook); returns `{redirect,token,url,user}` |
| 4.3 | `POST /sign-out` | delete session + cookies → `{success:true}` |
| 4.4 | `GET /list-sessions`, `POST /revoke-session {token}`, `/revoke-sessions`, `/revoke-other-sessions`, `POST /update-session` | revoke returns `{status:true}` |
| 4.5 | `POST /update-user` | rejects `email` (`EMAIL_CAN_NOT_BE_UPDATED`); `{status:true}` |
| 4.6 | `POST /verify-password {password}` | `{status:true}` |
| 4.7 | `POST /change-password {newPassword,currentPassword,revokeOtherSessions?}` | returns `{token,user}`; new session when revoking |
| 4.8 | `POST /send-verification-email`, `GET /verify-email?token&callbackURL` | HS256 JWT `{email,updateTo?}` exp = `EmailVerification.ExpiresIn` (default 1h); `SendOnSignUp`, `SendOnSignIn`, `AutoSignInAfterVerification`, before/after hooks; redirect when callbackURL |
| 4.9 | `POST /request-password-reset {email,redirectTo?}`, `GET /reset-password/:token?callbackURL`, `POST /reset-password {newPassword,token}` | verification identifier `reset-password:<token>`, value = userId, 1h; always `{status:true,message}`; `RevokeSessionsOnPasswordReset`; `OnPasswordReset` |
| 4.10 | `POST /change-email {newEmail,callbackURL?}` | `user.changeEmail.enabled`; unverified → update directly; verified → JWT with `updateTo` sent via `SendChangeEmailVerification` |
| 4.11 | `POST /delete-user {password?,token?,callbackURL?}`, `GET /delete-user/callback?token&callbackURL` | `user.deleteUser.enabled`, `SendDeleteAccountVerification`, `BeforeDelete/AfterDelete`, freshness required |
| 4.12 | Legacy aliases | Keep `/signup`, `/login`, … only when `Mode=Legacy` or `LegacyRoutes=true`; log deprecation |

Done when for each step: golden test vs TS server passes (06 §2) **and** the official
`better-auth/client` script in `06 §3` works end-to-end.

---

## Phase 5 – Security parity (M)

**5.1 Origin check & trusted origins** (F1, F3) – `src/security/origin.go`:
  for non-GET requests carrying cookies, `Origin`/`Referer` must match `BaseURL` origin or
  `TrustedOrigins` (supports `*.example.com`, `exp://` schemes, and a `func(r) []string`).
  Validate `callbackURL`, `redirectTo`, `errorCallbackURL`, `newUserCallbackURL`
  (relative paths allowed) → `403 INVALID_ORIGIN` / `INVALID_CALLBACK_URL`.
**5.2 CSRF fetch-metadata** (F2) – reject `Sec-Fetch-Site: cross-site` + `Sec-Fetch-Mode: navigate`
  on first-login POSTs (`CROSS_SITE_NAVIGATION_LOGIN_BLOCKED`).
**5.3 IP extraction** (F5) – default header `x-forwarded-for`, configurable list, IPv6 /64 subnet,
  `DisableIPTracking`. Used for `session.ipAddress` and rate limiting.
**5.4 Rate limiter** (F4) – `src/security/ratelimit/`: storage `memory` | `secondary-storage` |
  `database` (`rateLimit` table: `id,key,count,lastRequest`). Defaults `window=10s,max=100`,
  enabled when not in dev; built-in rules: `/sign-in/*`, `/sign-up/*`, `/change-password`,
  `/change-email` → `window=10,max=3`; `CustomRules map[path]Rule|false`. 429 +
  `X-Retry-After` header.
**5.5 DisabledPaths** (F6) – skip registration of listed paths.

---

## Phase 6 – Hooks, additional fields, plugin API v2 (M–L)

**6.1 Database hooks** (G1) – `DatabaseHooks{User,Session,Account,Verification}{Create,Update,Delete}{Before,After}`;
  `Before` may mutate data or return error to abort; implemented once in the repo layer
  (wrap `IAuthRepos`). Re-implement current `HookRegistry` events on top of it (keep API).
**6.2 Request hooks** (G2) – `Hooks{Before, After []HookEntry{Matcher func(*HookContext) bool, Handler}}`;
  `HookContext` gives path, body, headers, session, `ReturnedResponse` (after), ability to set
  cookies/headers or short-circuit.
**6.3 Additional fields** (C7) – `User.AdditionalFields map[string]FieldAttr{Type, Required, DefaultValue,
  Input bool, Returned bool}` (same for Session, Account, Verification). Storage: real columns
  added by migrator from the declaration; DTOs carry `map[string]any` merged into JSON.
**6.4 Plugin interface v2** (G3, G5)
  ```go
  type Plugin interface {
      ID() string
      Init(*InitContext) error
  }
  // optional capabilities (type-asserted):
  type WithSchema    interface{ Schema() []ModelSchema }         // tables/fields → migrator
  type WithEndpoints interface{ Endpoints() []Endpoint }         // Huma ops, path relative to BasePath
  type WithHooks     interface{ Hooks() Hooks }                   // before/after matchers
  type WithDBHooks   interface{ DatabaseHooks() DatabaseHooks }
  type WithRateLimit interface{ RateLimit() []RateLimitRule }
  type WithErrors    interface{ ErrorCodes() map[string]string }
  type WithOnRequest interface{ OnRequest(*http.Request) (*http.Request, *http.Response, error) }
  ```
  Keep `Migrator()/Services()/Routes()` as deprecated shims.
  `InitContext` gains `SessionManager`, `Cookies`, `Secret`, `Crypto`, `Options`.

---

## Phase 7 – Cookie cache & stateless (M, mostly port)

**7.1** Port `better-go-auth/core/services/auth/cookie_cache.go`: strategies `compact` (default),
  `jwt` (HS256), `jwe` (A256CBC-HS512, HKDF-SHA256 key from secret), chunking at ~4 KB
  (`session_data.0..n`), `MaxAge=5m`, `RefreshCache`, `Version` invalidation.
**7.2** `get-session` reads cache first unless `disableCookieCache`.
**7.3** Stateless mode: no DB & no secondary storage → cookie cache forced on, `jwe`, `MaxAge=ExpiresIn`.
Done when: a `session_data` cookie produced by the TS server is accepted by goauth (each strategy)
and vice-versa (port vectors from `better-go-auth/tests/e2e/cookie_cache_test.go`).

---

## Phase 8 – bearer + jwt plugins (replace the legacy JWT pair) (M)

**8.1 bearer** – accept `Authorization: Bearer <token>` (signed or unsigned when
  `RequireSignature=false`); respond with `set-auth-token` header on session creation and
  `Access-Control-Expose-Headers: set-auth-token`.
**8.2 jwt** – table `jwks{id, publicKey, privateKey(encrypted), createdAt, expiresAt?}`;
  default alg `EdDSA/Ed25519` (also ES256, RS256, PS256, ES512); `GET /token` → `{token}`;
  `GET /jwks` → JWKS; `set-auth-jwt` header on `get-session`; claims `sub=userId`,
  `iss/aud = BaseURL`, `exp = 15m`, payload = user (or `DefinePayload` func); key rotation.
**8.3** Mark Legacy `/refresh`, `/login` JWT flow deprecated; document migration
  (mobile: use bearer; services: verify via `/jwks`).

---

## Phase 9 – Social OAuth (XL)

**9.1 Provider interface** – port `better-go-auth/providers/oauth` and extend to better-auth's
  `OAuthProvider{ID, CreateAuthorizationURL(state, codeVerifier, scopes, redirectURI, loginHint),
  ValidateAuthorizationCode, RefreshAccessToken, GetUserInfo, VerifyIDToken, RevokeToken}`.
**9.2 State** – `account.StoreStateStrategy: "database"` (default; verification row identifier =
  random state, value = JSON `{callbackURL, codeVerifier, errorURL, newUserURL, link, expiresAt,
  requestSignUp}`) or `"cookie"` (encrypted `{prefix}.state`); PKCE S256 always.
**9.3 Endpoints** – `POST /sign-in/social` (redirect URL or `idToken` sign-in), `GET|POST /callback/:id`
  (form_post for Apple), `POST /link-social`, `POST /unlink-account {providerId,accountId?}`
  (`FAILED_TO_UNLINK_LAST_ACCOUNT`), `GET /list-accounts`, `POST /account-info`,
  `POST /refresh-token`, `POST /get-access-token` (auto-refresh).
**9.4 Account linking** – `account.accountLinking{Enabled, TrustedProviders, AllowDifferentEmails,
  UpdateUserInfoOnLink}`; `encryptOAuthTokens`; `mapProfileToUser`; `disableImplicitSignUp`.
**9.5 Providers in order**: google → github → discord → microsoft → apple (JWT client secret,
  form_post) → gitlab → facebook → linkedin → twitter → the remaining 26.
**9.6** `generic-oauth` plugin (`/sign-in/oauth2`, `/oauth2/callback/:providerId`, `/oauth2/link`)
  with OIDC discovery – covers most remaining providers cheaply.

---

## Phase 10 – Plugins

Follow [05-plugins.md](05-plugins.md) (ordered easy → hard: username, anonymous,
last-login-method, multi-session, one-time-token, email-otp, magic-link, admin re-align,
phone-number, organization re-align + teams, access control, two-factor, api-key, captcha,
haveibeenpwned, one-tap, device-authorization, passkey, oauth-provider/oidc, sso, scim, stripe).

---

## Phase 11 – Ecosystem (M–L)

- **11.1 Framework reach** – document Huma adapters (`humago` net/http, `humachi`, `humagin`,
  `humafiber`, `humaecho`) and expose `goauth.Handler() http.Handler` that mounts everything under
  `BasePath` for non-Huma apps.
- **11.2 Server API parity** – `auth.API.SignInEmail(ctx, body, headers)` style methods
  mirroring `auth.api.*`, returning `(resp, headers, error)`.
- **11.3 Schema CLI** – `go run github.com/better-go-auth/goauth/cmd/goauth generate|migrate`
  printing SQL for core + enabled plugins (mirror `@better-auth/cli generate`).
- **11.4 OpenAPI** – align operation IDs with better-auth `open-api` plugin; serve `/reference`.
- **11.5 i18n** – error message translation hook (better-auth `i18n` package).
- **11.6 Flip default** – `Mode=ModeCompat` default (v2.0); remove Legacy in v3.0.

---

## Milestones

| Version | Contains | Exit criteria |
|---|---|---|
| v1.2 | Phases 0–1 | primitives tested against TS vectors |
| v1.3 | Phase 2 | schema diff vs TS CLI = empty |
| v1.4 | Phases 3–4 | `better-auth/client` email/password flow passes |
| v1.5 | Phases 5–7 | security & cookie-cache parity tests pass |
| v2.0 | Phase 8 + admin/org re-align + Compat default | mobile (expo) client works via bearer |
| v2.x | Phases 9–10 | provider/plugin parity tracked in 05 |
| v3.0 | Legacy removed | – |
