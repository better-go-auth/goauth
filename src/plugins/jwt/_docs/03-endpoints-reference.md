# JWT Plugin: Endpoints Reference

The JWT plugin registers four dedicated endpoints on the HTTP API and attaches an after-hook middleware to session retrieval.

All endpoints are registered under `basePath` (default: `/api/auth`). In addition, `GET /jwks` is registered at the root path for standard JWKS discovery.

---

## 1. `GET /api/auth/jwks` (and `GET /jwks`)

### Description
Returns the active JSON Web Key Set (JWKS) containing all valid public keys formatted according to RFC 7517 and RFC 8037.

External consumers, API gateways, and client libraries fetch this endpoint to obtain public keys for verifying JWT signatures without accessing the database.

### Request
- **Method**: `GET`
- **Path**: `/api/auth/jwks` (alias: `/jwks`)
- **Headers**: None required
- **Authentication**: Public (no credentials required)

### Response (`200 OK`)
```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "7ctgI413H5rRTTesWMUb6PwzNaJu-4pBmvJxDDx5bwc",
      "kid": "P5UwR73KfGQX3h4VIRXkN0YQiubW754Z",
      "alg": "EdDSA",
      "use": "sig"
    }
  ]
}
```

### Key Parameters:
- `kty`: `"OKP"` (Octet Key Pair for Edwards-curve keys).
- `crv`: `"Ed25519"`.
- `x`: Base64URL-encoded (unpadded) public key bytes (32 bytes).
- `kid`: Key Identifier string matching the `kid` header in issued JWTs.
- `alg`: `"EdDSA"`.
- `use`: `"sig"` (signature verification).

---

## 2. `GET /api/auth/token`

### Description
Generates and returns a signed JWT token representing the caller's currently active session.

### Request
- **Method**: `GET`
- **Path**: `/api/auth/token`
- **Authentication**: Required. Must pass either:
  - Cookie: `better-auth.session_token=<session_token>`
  - Header: `Authorization: Bearer <session_token>`

### Response (`200 OK`)
```json
{
  "token": "eyJhbGciOiJFZERTQSIsImtpZCI6IlA1VXdSNzNLZkdR..."
}
```

### Error Responses:
- `401 Unauthorized`: No active session found or invalid credentials.
- `500 Internal Server Error`: Key creation or signing failure.

---

## 3. Server-only: `signJWT` (no HTTP route)

### Description
In better-auth, `POST /sign-jwt` is `SERVER_ONLY` (callable only as `auth.api.signJWT`). goauth does **not**
register it over HTTP: an unauthenticated caller could otherwise mint a JWKS-valid token for any `sub`.
`POST /api/auth/sign-jwt` answers `404`. Sign from Go instead:

```go
tok, err := jwtPlugin.SignJWT(ctx, map[string]any{
	"sub":    "custom-subject-123",
	"role":   "admin",
	"scopes": []string{"read", "write"},
}, &jwtplugin.SignJWTOptions{ExpirationTime: time.Hour}) // opts may be nil
// equivalently: jwtPlugin.Service().SignJWT(ctx, payload, opts)
```

- `payload`: the claims (nil is an empty payload). Missing `iat`, `exp`, `iss` and `aud` are filled in.
- `SignJWTOptions` (better-auth's `overrideOptions.jwt`): `Issuer`, `Audience`, `ExpirationTime`.
- The header carries the active key's `alg` and `kid`.

---

## 4. Server-only: `verifyJWT` (no HTTP route)

### Description
Also `SERVER_ONLY` in better-auth (`auth.api.verifyJWT`); `POST /api/auth/verify-jwt` answers `404`.
Verifies a token against the stored keys (signature with the algorithm of the key named by `kid`, `exp`,
`iss`, `aud`, presence of `sub`) and returns its claims:

```go
claims, err := jwtPlugin.VerifyJWT(ctx, token, "") // "" = configured issuer; err != nil when invalid
```

---

## 5. Hook: `set-auth-jwt` on `/get-session`

### Description
Attaches to `GET /api/auth/get-session` and `POST /api/auth/get-session`.

Whenever an active session is found:
1. The middleware signs a JWT containing the user profile and session info.
2. The signed JWT is placed into the HTTP response header:
   ```http
   set-auth-jwt: eyJhbGciOiJFZERTQSIsImtpZCI6IlA1VXdSNzNLZkdR...
   ```
3. The header is exposed in CORS via:
   ```http
   Access-Control-Expose-Headers: set-auth-jwt
   ```
4. Frontend clients using `@better-auth/client`'s `jwtClient()` plugin automatically read this header from responses and cache the token for subsequent API calls.

To disable this behavior, configure:
```go
jwtplugin.New(cfg, jwtplugin.WithDisableSettingJwtHeader(true))
```
