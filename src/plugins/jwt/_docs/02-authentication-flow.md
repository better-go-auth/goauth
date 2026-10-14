# JWT Plugin: Authentication & Authorization Flow

This document details the lifecycle of JSON Web Tokens (JWT) in `goauth`: how tokens are generated, how they are sent to clients, and how incoming requests carrying a JWT are authenticated and authorized.

---

## 1. How Tokens are Issued

There are two primary ways JWT tokens are issued to clients:

### Flow A: Automatic Issuance via `/get-session` Hook (`set-auth-jwt`)
Better Auth specifies an after-hook on session retrieval: whenever a client calls `GET /api/auth/get-session` (or `POST /api/auth/get-session`), the JWT plugin attaches a fresh, signed JWT in the `set-auth-jwt` response header.

```
Client (Web / Mobile)                 GoAuth Server                     Database
       |                                   |                                |
       |--- 1. GET /api/auth/get-session ->|                                |
       |    (Cookie: better-auth.session_token                              |
       |     OR Authorization: Bearer <token>)                              |
       |                                   |--- 2. Resolve Session -------->|
       |                                   |<-- 3. Return Session/User -----|
       |                                   |
       |                                   |--- 4. JWT Plugin Hook runs ----|
       |                                   |    - Check active signing key  |
       |                                   |    - Sign JWT with Ed25519     |
       |                                   |    - Add "set-auth-jwt" header |
       |                                   |    - Expose header in CORS     |
       |                                   |
       |<-- 5. Response 200 OK ------------|
       |    Headers:                       |
       |      set-auth-jwt: <signed.jwt>   |
       |    Body: { session: ..., user: ... }
```

### Flow B: Explicit Issuance via `GET /api/auth/token`
Clients can also explicitly request a JWT token for their active session:
1. Client sends `GET /api/auth/token` with an active session cookie or bearer token.
2. The handler resolves the session, builds the JWT payload, signs it using the active Ed25519 private key, and returns:
   ```json
   { "token": "eyJhbGciOiJFZERTQS..." }
   ```

---

## 2. Authenticating Incoming Requests with a JWT

When a request arrives at an endpoint with an `Authorization: Bearer <token>` header, the server determines the token type and executes the verification pipeline.

```
Incoming Request:
"Authorization: Bearer <token>"
       |
       v
Is it a JWT? (strings.Count(token, ".") == 2)
       |
       +---> YES (JWT Token: 3 parts)
       |       |
       |       v
       |     1. Decode Header without verification
       |        - Extract "kid" (Key ID) and "alg" ("EdDSA")
       |       |
       |       v
       |     2. Fetch Matching Public Key
       |        - Look up JWK by "kid" in database or in-memory cache
       |        - Verify algorithm matches "EdDSA"
       |       |
       |       v
       |     3. Verify Digital Signature
       |        - Use Ed25519 public key to verify signature over Header.Payload
       |        - If signature invalid -> 403 Forbidden / 401 Unauthorized
       |       |
       |       v
       |     4. Validate Claims
       |        - exp: Must not be expired (now < exp)
       |        - nbf / iat: Must be valid
       |        - iss / aud: Must match expected issuer/audience
       |       |
       |       v
       |     5. Populate Request Context
       |        - Context is enriched with UserID, Claims, Role
       |        - Handler proceeds to execute business logic
       |
       +---> NO (Opaque Session Token: 1 or 2 parts)
               |
               v
             Processed by Bearer / Session Manager
             - Look up session by token in cache / database
```

---

## 3. What Happens If `/get-session` receives a JWT?

Better Auth client requests `/get-session` using either session cookies or session bearer tokens. However, in microservice architectures or when a client passes a JWT:

1. **Header Parsing**: The request headers are parsed for `Authorization: Bearer <jwt>` and `Cookie`.
2. **Session Claims Resolution**:
   - The session manager checks for a standard session token (`token` or `token.signature`).
   - If a JWT is supplied directly, `SessionClaimsResolver` / `JWTService.VerifyJWT` parses and verifies the token against the active JWKS public keys.
   - The subject (`sub`) in the verified JWT payload contains the `userId`.
   - The user record is retrieved, validating that the account is active.
3. **Response**: The session endpoint returns the authenticated user snapshot. If the request was valid, a fresh JWT is re-emitted in `set-auth-jwt`.

---

## 4. Decentralized Microservice Verification (Offline JWKS)

The primary reason to use the JWT plugin over traditional session tokens is **stateless decentralized verification**:

```
[ Frontend Client ] 
        |
        | 1. Login to GoAuth Server
        v
 [ GoAuth Server ] ----> Issues JWT signed with Ed25519 Private Key
        |
        | 2. Client sends requests with "Authorization: Bearer <jwt>"
        v
 [ Microservice A / API Gateway ]
        |
        | 3. First request: Fetches Public Keys from GoAuth:
        +-----> GET https://auth.example.com/api/auth/jwks
        |       Caches Public Keys in memory (e.g. for 1 hour)
        |
        +-----> 4. Verifies Ed25519 signature entirely in-memory!
                   NO database call to GoAuth needed!
                   Zero latency overhead!
```

- Microservices do not need a database connection to GoAuth.
- High throughput: tens of thousands of requests per second can be verified statelessly.
- If a signing key is rotated, the microservice fetches the updated keys from `/jwks` when encountering a new `kid`.
