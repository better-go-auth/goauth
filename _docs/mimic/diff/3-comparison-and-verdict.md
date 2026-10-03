# 3 – Comparison, verdict and what better-auth adds

Read [1-better-auth-session-cookies.md](1-better-auth-session-cookies.md) and
[2-goauth-session-cookies.md](2-goauth-session-cookies.md) first.

## 3.1 Side by side

| Aspect | better-auth | goauth (today) |
|---|---|---|
| Model | Stateful opaque session token | Stateless JWT access + rotating JWT refresh |
| Credential in browser | 1 signed HttpOnly cookie (`better-auth.session_token`) | 2 unsigned JWT cookies (`access-token`, `refresh-token`), not read by the server |
| Credential for mobile/API | `bearer` plugin (same token in a header) | `Authorization: Bearer <access JWT>` (built in) |
| Per-request cost | 1 DB/Redis lookup, or 0 inside the cookie-cache window | 0 (signature check) + 1 Redis `EXISTS` when a store is configured |
| Lifetime | 7 d, sliding (DB write at most once/day) | access 60 min; refresh 7 d, sliding on each refresh |
| Client refresh logic | none – the cookie is refreshed transparently by `get-session` | client must call `/refresh` before the access token expires |
| Revocation | immediate (≤ cookie-cache maxAge if enabled) | **up to 60 min**, immediate only with secondary storage |
| Role/ban change visibility | next request | next refresh / token expiry |
| Sessions per user | unlimited, listable, individually revocable | **1** (login wipes the others) |
| Remember me | yes (`dont_remember`, 1-day session, browser-session cookie) | no |
| Fresh-session gate | yes (`freshAge`) | no |
| Sensitive-op bypass of cache | yes (`sensitiveSessionMiddleware`) | n/a |
| IP / User-Agent on session | yes | no |
| Cookie signing | HMAC-SHA256 | none (JWT signature only) |
| Secure / `__Secure-` / cross-subdomain | automatic + configurable | `Secure=false` hard-coded |
| Cookie size handling | chunking (`.0…n`) | none |
| Token storage at rest | **plaintext token** in DB/Redis | **argon2 hash** of refresh token |
| Refresh-token rotation | n/a (no refresh token) | yes (old token invalid after refresh) |
| Session cache | cookie cache: compact / jwt / jwe, versioned | – |
| Redis session storage | full (sessions + per-user index) | revocation blacklist only |
| Stateless (no DB) mode | yes (JWE cookie) | no (needs the DB for refresh) |
| Service-to-service verification | `jwt` plugin: asymmetric JWT + JWKS | share the HS256 secret |
| Org/role context | `session.activeOrganizationId` (server-side, changeable) | `activeOrgId`/`activeOrgRole` claims (frozen until refresh, lost on refresh – bug G3) |
| Error format | `{code, message}` JSON, 401/403 | plain text, 403 for "no token" |

## 3.2 Verdict

**Overall, better-auth's design is better** for a general-purpose auth library. It is simpler
for clients, safer by default, and has far more features. goauth's design has two real
advantages worth keeping.

### Where better-auth is better

1. **Revocation actually works.** Logout, ban, password reset and "sign out other devices"
   take effect immediately. In goauth, without Redis, an access token stays valid for up to an hour after logout (G1).
2. **Simpler clients.** No refresh choreography, no token storage in JS, no race between parallel
   refresh calls. Browsers just send the cookie.
3. **Safer browser defaults.** One HttpOnly, signed, `Secure`/`__Secure-` cookie plus origin/CSRF checks.
   goauth hands JWTs to the client in the response body (they end up in JS-accessible storage)
   and sets insecure cookies.
4. **Multi-device sessions** with listing and per-device revocation; goauth allows one session.
5. **Fresh state.** Roles, bans and the active org are read from the server, so they never go stale in a token.
6. **Tunable performance.** The cookie cache gives JWT-like "no DB hit" reads with bounded staleness,
   versioned invalidation and an authoritative bypass for sensitive operations. You get both models in one.
7. **Lower write load.** The `updateAge` throttle means at most one session write per day per session;
   goauth runs an argon2 hash and a DB upsert on every refresh (hourly per client).
8. **Ecosystem compatibility.** The official clients (web, React, Expo, Electron) expect this model.

### Where goauth is better (keep these)

1. **Hashed tokens at rest.** goauth stores only a hash of the refresh token. better-auth stores the
   session token in plaintext, so a DB/Redis read leak = session hijack.
   → Possible goauth extension: store `SHA-256(token)` in `session.token` behind an option
   (`Session.HashTokens`). Note that this **breaks DB-level compatibility** with a TS server
   sharing the same DB, so it must be off in "shared DB" mode.
2. **Zero-lookup verification for APIs/microservices.** A JWT can be verified anywhere without DB access.
   → better-auth covers this with the `jwt` plugin (asymmetric + JWKS, which is better than a shared HS256
   secret). goauth should implement that plugin and drop the custom HS256 pair.
3. **Refresh-token rotation.** A good practice for long-lived mobile tokens. With better-auth's bearer
   model the long-lived token is the session token itself (no rotation). goauth could keep rotation for
   the bearer flow as an opt-in extension (`bearer.RotateOnRefresh`) without affecting cookie clients.
4. **Rich claims (org role) for fast RBAC.** Keep this by putting `activeOrganizationId` on the session
   and caching the member role in the cookie cache or JWT payload (`jwt.definePayload`).

## 3.3 Features better-auth has that goauth lacks

| Feature | better-auth option / mechanism |
|---|---|
| Opaque session tokens with sliding expiry | `session.expiresIn`, `session.updateAge` |
| Disable / defer refresh | `session.disableSessionRefresh`, `session.deferSessionRefresh` (+ `needsRefresh`) |
| Remember me | `rememberMe` body flag, `dont_remember` cookie |
| Fresh session requirement | `session.freshAge`, `freshSessionMiddleware` |
| Authoritative read for sensitive ops | `sensitiveSessionMiddleware`, `disableCookieCache` |
| Cookie cache (3 strategies, versioning, auto-refresh, chunking) | `session.cookieCache.{enabled,strategy,maxAge,version,refreshCache}` |
| Stateless mode | no DB → JWE cookie session |
| Secondary-storage sessions | `secondaryStorage`, `storeSessionInDatabase`, `preserveSessionInDatabase`, `active-sessions-<userId>` index |
| Multiple sessions per user + management API | `list-sessions`, `revoke-session(s)`, `revoke-other-sessions`, `update-session` |
| Session additional fields | `session.additionalFields` |
| Session DB hooks | `databaseHooks.session.{create,update,delete}.{before,after}` |
| IP / UA tracking & IPv6 subnetting | `advanced.ipAddress.*` |
| Cookie configuration | `advanced.cookiePrefix`, `useSecureCookies`, `crossSubDomainCookies`, `cookies[name]`, `defaultCookieAttributes` |
| Signed cookies | HMAC-SHA256 with `secret` (+ secret rotation support) |
| Cookie scrubbing on sign-out / 2FA | `deleteSessionCookie`, `expireCookie` |
| Account cookie (OAuth tokens cache) | `account.storeAccountCookie` |
| Origin / CSRF protection for cookie auth | `trustedOrigins`, fetch-metadata checks |
| Bearer transport | `bearer` plugin |
| Asymmetric JWT + JWKS | `jwt` plugin |
| Multi-account in one browser | `multi-session` plugin |
| Impersonation sessions | admin plugin (`impersonatedBy`, `admin_session` cookie) |
| Custom session response | `custom-session` plugin |
| Client helpers | `getSessionCookie()` / `getCookieCache()` for edge middleware (e.g. Next.js) |

## 3.4 Recommended path for goauth

These map onto the roadmap phases in [../03-roadmap.md](../03-roadmap.md):

1. **Fix now, before any compat work** (small and independent) ✅ done:
   - G2: remove `ClearSession: true` from login (or make it an option).
   - G3: carry `ActiveOrgID`/`OrgRole` from the existing session on refresh.
   - G4: re-check expiry, ban and active status in `ResetToken`.
   - G7: replace argon2 with SHA-256 for refresh-token hashing.
   - G8: set `Secure` from config/BaseURL; clear cookies on logout.
   - G1: default `CheckRevocationInDb=true` when no secondary storage is configured.
2. **Phase 1.3 / 1.7**: signed `better-auth.session_token` cookie + cookie manager.
3. **Phase 3**: SessionManager (opaque token, sliding refresh, rememberMe, freshAge, Redis layout)
   and a cookie-or-bearer session middleware; `get-session`.
4. **Phase 7**: cookie cache (port from better-go-auth) to get back the "no DB hit" property.
5. **Phase 8**: `bearer` + `jwt` plugins replace the access/refresh pair; keep refresh rotation and
   hashed tokens as opt-in goauth extensions; Legacy mode keeps the current flow until v3.
