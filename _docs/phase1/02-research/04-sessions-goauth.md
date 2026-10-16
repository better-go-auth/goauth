# 04 – How goauth sessions & cookies work today

Sources: `src/app/core/session/session.service.go`, `src/app/core/auth/auth.service.go`,
`src/app/core/auth/auth.handler.go`, `src/common/middleware/middleware.go`,
`src/providers/revocation_store.go`, `src/providers/token/jwt-token/jwt_managers.go`,
`src/app/repository/gormauth/session_repo.go`, `goauth.options.go`.

## 2.1 The core idea

goauth uses a **JWT access token + JWT refresh token pair**, both HS256. The
access token is verified **statelessly** on each request. A server-side session
row exists mostly so refresh tokens can be validated and sessions revoked.

```
login ─▶ { access_token (60 min), refresh_token (7 d) }   (body + cookies)
request ─Authorization: Bearer <access>─▶ verify HS256 ─▶ (optional) revocation check ─▶ claims in ctx
POST /refresh {token: <refresh>} ─▶ new pair, same session id
POST /logout  {token: <refresh>} ─▶ delete session row + blacklist session id
```

## 2.2 Tokens

| | Access token | Refresh token |
|---|---|---|
| Algorithm | HS256, `SessionConfig.AccessSecret` | HS256, `RefreshSecret` (falls back to AccessSecret) |
| Lifetime | `AccessExpireMin` (default 60 min) | `RefreshExpireMin` (default 7 d) |
| Claims | `userId, sessionId, role, activeOrgId, activeOrgRole, iat, exp, iss="better-go-auth"` | same |
| Stored | no | **argon2 hash** in `session.hashed_token` |

## 2.3 The session record (`auth_sessions`)

| Field | Value |
|---|---|
| `id` | ULID |
| `session_id` | `uuid.New()` (unique) – also the `sessionId` claim |
| `user_id`, `role` | owner and role at login time |
| `hashed_token` | argon2(refresh token) |
| `expires_at` | now + RefreshExpireMin |
| `active_org_id`, `org_role_id`, `device_token` | from login options |
| `blacklisted`, `blacklisted_on`, `revoked_at`, `last_used_at` | revocation bookkeeping (mostly unused) |

Written with `UpsertSession` (conflict on `session_id` → update `hashed_token, device_token,
active_org_id, expires_at`).

## 2.4 Flows

**Login** (`auth.service.go#Login`): checks password → `CreateSession(…, ClearSession: true)`.
`ClearSession` **deletes every existing session of the user**, so each login logs out all
other devices. Returns `{auth_tokens, user_data}` in a `GResp` envelope and sets two cookies.

**Refresh** (`ResetToken`): validates the refresh JWT → loads the user → loads the session by
`sessionId` → argon2-compares the token with `hashed_token` → `CreateSession(sameSessionId, role, userId, nil)`.
The upsert replaces the hash, so **the old refresh token stops working** (rotation).
`expires_at` slides forward by 7 days.

**Logout**: needs the **refresh token in the body**. It validates it and the hash, deletes the
row, fires `SessionRevoked`, and writes `blacklist:<sessionId>` to secondary storage (TTL = refresh lifetime).

**Request authentication** (`AuthMiddleware.Authenticate`):
1. Reads **only** the `Authorization: Bearer` header (a TODO says to also read cookies).
2. Verifies the HS256 signature and expiry with AccessSecret.
3. `RevocationStore.IsRevoked(sessionId)`:
   - secondary storage: `blacklist:<id>` or `revoked:session:<id>` exists → revoked
   - only if `CheckRevocationInDb` (default **false**): DB row missing/blacklisted/revoked/expired → revoked
4. Puts the claims, `userId` and `activeOrgId` into the Huma context.

**Authorization**: `Authorize(operationID, roles)` checks the `role` claim, or a
`DynamicRoleResolver` when one is configured. `AuthorizeOrg` checks the `activeOrgRole` claim.

**Session endpoints**: `GET /session` (list), `POST /session/{id}` (revoke one).

## 2.5 Cookies

`auth.handler.go#CreateCookie`:

| Cookie | Value | Attributes |
|---|---|---|
| `access-token` | raw access JWT | `HttpOnly; Path=/; SameSite=Lax; Expires=now+60m`, **`Secure=false` hard-coded**, no Domain |
| `refresh-token` | raw refresh JWT | same, Expires=now+7d |

- No prefix or `__Secure-` handling, no configuration (the `config.Cookie` struct is unused).
- Cookies are **set but never read**: the middleware, `/refresh` and `/logout` only use the header/body.
- Sign-out does not clear them.

## 2.6 Configuration that exists but is not wired

`config.Session{ExpiresIn, UpdateAge, FreshAge, DisableSessionRefresh, StoreSessionInDatabase}`,
`CookieCacheStrategy` (compact/jwt/jwe), `config.Cookie{…}`, `SessionConfig.RevocationPrefix`,
`BlacklistPrefix`. All are declared but unused; only `JwtVar` and `CheckRevocationInDb` take effect.

## 2.7 Issues found while reading the code

| # | Issue | Impact |
|---|---|---|
| G1 | Without secondary storage, `BlacklistSession` is a no-op and `CheckRevocationInDb=false` | **Logout, revoke, ban and password reset do not invalidate access tokens** for up to 60 min |
| G2 | `ClearSession: true` on every login | Only **one session per user**; logging in on a phone logs out the laptop |
| G3 | Refresh calls `CreateSession(…, nil)` → upsert sets `active_org_id = NULL`, claims lose `activeOrgId/activeOrgRole` | Active organization **lost on every refresh** |
| G4 | Refresh does not check `expires_at`, ban status, `Active` or account status | Banned or disabled users can keep refreshing (until the row is deleted) |
| G5 | Role and org role are frozen in the JWT | Role changes apply only after refresh or expiry |
| G6 | Refresh-token reuse is not detected (an old token simply fails) | No theft detection or session-family revocation |
| G7 | argon2 (memory-hard) runs on each login/refresh/logout for a high-entropy token | High CPU/memory per call → easy DoS amplification; SHA-256 is enough for random tokens |
| G8 | Cookies `Secure=false`, unread, never cleared on logout | Insecure over HTTPS, and confusing |
| G9 | Middleware errors are plain text, `403 Token Not Valid` for a missing token | Not machine-readable; wrong status (should be 401) |
| G10 | Hook errors ignored (`_ = TriggerBeforeSessionCreate`) | Hooks cannot veto session creation |
| G11 | No IP/User-Agent capture, no freshness, no rememberMe | Weaker session management UX/security |
| G12 | Blacklist key prefixes hard-coded (`blacklist:`) while `RevocationPrefix/BlacklistPrefix` config is ignored | Misleading config |
| G13 | Only `RefreshSecret`/`AccessSecret` HS256 and shared secret | Other services must hold the signing secret to verify tokens (no JWKS) |
