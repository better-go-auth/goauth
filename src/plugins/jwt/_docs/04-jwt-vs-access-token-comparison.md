# Comparison: JWT Plugin vs Access-Token Plugin

Both the **`jwt`** plugin and the **`access-token`** plugin deal with tokens in HTTP headers (`Authorization: Bearer <token>`), but they originate from completely different architectural paradigms and serve different use cases.

This document breaks down their differences, overlapping capabilities, and decision criteria.

---

## 1. Quick Summary

| Feature / Dimension | `jwt` Plugin (Better Auth Standard) | `access-token` Plugin (GoAuth Legacy) |
| :--- | :--- | :--- |
| **Specification** | Official [Better Auth `jwt()` plugin](https://better-auth.com/docs/plugins/jwt) specification | Internal `better-go-auth` legacy dual-token architecture |
| **Cryptography** | **Asymmetric** (Ed25519 / EdDSA) | **Symmetric** (HMAC-SHA256 / HS256) |
| **Public Key Discovery** | **Yes** — Public JWKS endpoint (`GET /jwks`) | **No** — Shared symmetric secret (`AccessSecret`) |
| **Verification Statefulness** | **Fully Stateless & Decentralized** (can be verified by any microservice or gateway using only public keys) | **Centralized / Stateful** (requires database/Redis session lookup and revocation store) |
| **Token Types** | Single self-contained JWT token | Dual tokens: Short-lived Access Token + Long-lived Refresh Token |
| **Revocation Strategy** | Expiration-based (short lifespan, e.g. 15m) + Key Rotation | Active blacklist / Redis revocation store per token or session |
| **Client SDK Support** | Built-in `@better-auth/client` `jwtClient()` plugin | Custom client fetch logic for token refresh |
| **Database Tables** | `jwks` table (stores encrypted Ed25519 key pairs) | Uses core tables (`users`, `sessions`, `accounts`) |
| **Response Headers** | `set-auth-jwt` on `/get-session` | `set-auth-token` (bearer session) / cookies |
| **Custom Signing API** | Yes (`POST /sign-jwt`, `POST /verify-jwt`) | No custom signing endpoints |

---

## 2. Overlapping Features (Where They Agree)

1. **Bearer Header Transport**:
   Both plugins use the standard HTTP `Authorization: Bearer <token>` header to authenticate requests.

2. **User Identity Claims**:
   Both encode core user identity claims in the token payload:
   - `sub` / `userId`: Unique identifier of the authenticated user.
   - `email`: User's primary email address.
   - `iat` and `exp`: Issuance timestamp and expiration timestamp.

3. **Protection of Endpoints**:
   Both can authorize protected routes in the Huma API. `goauth`'s central authentication middleware recognizes both formats.

4. **Session Association**:
   Both link an active session to a user account, ensuring the token is issued only after valid authentication (password, OTP, social, etc.).

---

## 3. Key Differences Explained

### 3.1 Asymmetric vs Symmetric Cryptography
- **`jwt` Plugin (Asymmetric Ed25519)**:
  - Uses a **public/private key pair**.
  - The auth server holds the private key (encrypted at rest) and signs tokens.
  - Anyone in the world (or inside your internal VPC) can fetch the **public key** from `/jwks` and verify tokens.
  - Zero risk: You can distribute the public keys anywhere without compromising signing ability.
- **`access-token` Plugin (Symmetric HS256)**:
  - Uses a **single shared secret key** (`AccessSecret`).
  - To verify a token, a service MUST know the secret key.
  - If a microservice has the secret key to verify tokens, it can also forge valid tokens! This prevents safe verification outside the trusted auth service.

### 3.2 Decentralized Microservices vs Centralized Store
- **`jwt` Plugin**:
  - Designed for **modern microservice architectures**.
  - Service A, Service B, and the API Gateway fetch the JWKS once and cache it in memory.
  - Requests carrying a JWT are verified 100% in-memory with zero network calls and zero database queries.
- **`access-token` Plugin**:
  - Designed for **traditional monolithic or session-centric setups**.
  - Every incoming access token is checked against the database or Redis revocation store to see if the session was revoked or blacklisted.

### 3.3 Token Refresh & Lifecycle
- **`access-token` Plugin**:
  - Implements the OAuth2-style refresh token pattern.
  - Client stores a refresh token and repeatedly calls `POST /token/refresh` to get a new access token when it expires.
- **`jwt` Plugin**:
  - In Better Auth, the **session** (cookie or bearer) is the source of truth for refreshing.
  - The client calls `GET /api/auth/get-session`, and the server automatically returns a refreshed JWT in the `set-auth-jwt` response header.
  - There is no separate refresh token; the session itself manages continuous access.

---

## 4. When to Use Which?

### Choose the `jwt` Plugin if:
- You are building a frontend using the official `@better-auth/client` with `jwtClient()`.
- You have **downstream microservices**, API gateways (Kong, Traefik, AWS API Gateway), or serverless functions (Cloudflare Workers, AWS Lambda) that need to verify user authentication independently.
- You want standard RFC 7517 / RFC 8037 compliance with public key rotation and zero-database verification overhead.
- You need arbitrary token signing and verification APIs (`/sign-jwt`, `/verify-jwt`).

### Choose the `access-token` Plugin if:
- You are maintaining legacy client integrations that rely on OAuth2-style dual-token flow (`access_token` + `refresh_token` endpoints).
- You require instantaneous token-level blacklisting in Redis on every single request.
- You are migrating an existing Go application that already depends on `AccessTokenConfig` and symmetric HS256 verification.

### Can they be used together?
**Yes.** `goauth` is modular:
- You can enable both plugins simultaneously.
- When an incoming request arrives with `Authorization: Bearer <token>`, `goauth` checks if the token is a 3-part JWT or a session/bearer token, allowing both legacy and modern JWT clients to communicate with the exact same server without conflict.
