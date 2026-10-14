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

## 3. `POST /api/auth/sign-jwt`

### Description
Signs an arbitrary payload using the server's active Ed25519 private key. This endpoint is useful for backend services or authorized clients that need to issue custom JWTs (e.g. for service-to-service calls or custom claims).

### Request
- **Method**: `POST`
- **Path**: `/api/auth/sign-jwt`
- **Headers**: `Content-Type: application/json`
- **Body**:
  ```json
  {
    "payload": {
      "sub": "custom-subject-123",
      "role": "admin",
      "scopes": ["read", "write"]
    },
    "header": {
      "typ": "JWT"
    },
    "expirationTime": "1h"
  }
  ```

### Fields:
- `payload` (required): JSON object containing the claims to encode.
- `header` (optional): Custom header values to include (the system automatically injects `alg: "EdDSA"` and `kid: "<active-key-id>"`).
- `expirationTime` (optional): Expiration duration string (e.g., `"15m"`, `"1h"`, `"7d"`) or numeric seconds. Defaults to `config.JWT.ExpirationTime` (15 minutes).

### Response (`200 OK`)
```json
{
  "token": "eyJhbGciOiJFZERTQSIsImtpZCI6IlA1VXdSNzNLZkdRWDNoNFZJ..."
}
```

---

## 4. `POST /api/auth/verify-jwt`

### Description
Cryptographically validates a JWT token against the server's JWKS public keys and returns the decoded payload if valid.

### Request
- **Method**: `POST`
- **Path**: `/api/auth/verify-jwt`
- **Headers**: `Content-Type: application/json`
- **Body**:
  ```json
  {
    "token": "eyJhbGciOiJFZERTQSIsImtpZCI6IlA1VXdSNzNLZkdRWDNoNFZJ..."
  }
  ```

### Response (`200 OK`)
When the token is valid, the decoded claims payload is returned:
```json
{
  "payload": {
    "iss": "http://localhost:3000",
    "sub": "custom-subject-123",
    "aud": "http://localhost:3000",
    "exp": 1791972759,
    "iat": 1791971859,
    "role": "admin",
    "scopes": ["read", "write"]
  }
}
```

### When Token is Invalid or Expired:
- Returns `200 OK` with:
  ```json
  {
    "payload": null
  }
  ```
- Or returns `400 Bad Request` if the token string is malformed.

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
