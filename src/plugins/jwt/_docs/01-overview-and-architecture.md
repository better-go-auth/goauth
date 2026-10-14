# JWT Plugin: Overview & Architecture

The **JWT Plugin** provides official [Better Auth](https://better-auth.com) feature parity for JSON Web Tokens (JWT) and JSON Web Key Sets (JWKS). It enables decentralized authentication, allowing external services, API gateways, microservices, and frontends to cryptographically verify user identity without querying the central authentication database.

---

## 1. Core Architectural Pillars

### 1.1 Asymmetric Cryptography (Ed25519 / EdDSA)
- Better Auth uses **Ed25519** (an Edwards-curve digital signature algorithm over Curve25519) with the `EdDSA` signature algorithm.
- Ed25519 provides 128-bit security level with high performance, resistance to side-channel attacks, and compact signatures (64 bytes) and keys (32 bytes).
- Standard RFC 8037 (`Crv: "Ed25519"`, `Kty: "OKP"`) is used for encoding keys into standard JWK format.

### 1.2 Public JWKS Endpoint (`/jwks`)
- The plugin publishes the active public keys at `GET /api/auth/jwks` (and alias `GET /jwks`).
- External consumers (e.g. Node.js with `jose`, Go microservices with `golang-jwt`, Envoy/Kong gateways) can fetch and cache this JWKS set to verify tokens completely offline and statelessly.

### 1.3 Secure Storage with Symmetric Encryption at Rest
- Private keys must never leak, even if the database is dumped or compromised.
- Before storing the Ed25519 private key in the `jwks` database table, the private key JWK is encrypted using **XChaCha20-Poly1305** symmetric authenticated encryption via the master `AuthConfig.Secret`.
- The public key is stored in plain JSON string format so it can be served directly.

### 1.4 Automatic Key Rotation & Grace Periods
- Keys can be rotated periodically based on `RotationInterval` (e.g., every 30 days).
- When a key expires and a new key is generated, the older keys remain in the `jwks` table and continue to be served in the `/jwks` set for the duration of the configured `GracePeriod` (default: 30 days).
- This ensures that tokens issued right before key rotation remain valid until their individual expiration dates.

---

## 2. Database Model: `jwks` Table

The plugin manages a dedicated database table:

```go
type JWK struct {
    ID         string     `gorm:"primaryKey;column:id;type:varchar(255)" json:"id"`
    PublicKey  string     `gorm:"column:public_key;type:text;not null" json:"publicKey"`
    PrivateKey string     `gorm:"column:private_key;type:text;not null" json:"privateKey"`
    CreatedAt  time.Time  `gorm:"column:created_at;autoCreateTime" json:"createdAt"`
    ExpiresAt  *time.Time `gorm:"column:expires_at" json:"expiresAt,omitempty"`
    Alg        string     `gorm:"column:alg;type:varchar(64)" json:"alg"`
    Crv        string     `gorm:"column:crv;type:varchar(64)" json:"crv"`
}
```

### Fields:
- `id`: Unique Key ID (`kid`), a 32-character secure random identifier.
- `public_key`: JSON string of the RFC 8037 public key (containing `kty`, `crv`, `x`, `kid`, `alg`, `use`).
- `private_key`: Hex-encoded XChaCha20-Poly1305 ciphertext of the private key JSON (containing `d`), or raw JSON if encryption is disabled.
- `created_at`: Key creation timestamp.
- `expires_at`: When the key stops being used for *signing* new tokens.
- `alg`: Signature algorithm (`"EdDSA"`).
- `crv`: Curve (`"Ed25519"`).

---

## 3. JWT Claims Structure

Tokens issued by the plugin contain standard OIDC / RFC 7519 claims:

```json
{
  "iss": "http://localhost:3000",
  "sub": "01M4WXH6XK2F0MCT7KGTTTZR3C",
  "aud": "http://localhost:3000",
  "exp": 1791972759,
  "iat": 1791971859,
  "id": "01M4WXH6XK2F0MCT7KGTTTZR3C",
  "name": "Alex Developer",
  "email": "alex@example.com",
  "emailVerified": true,
  "image": null,
  "createdAt": "2026-10-14T09:57:39Z",
  "updatedAt": "2026-10-14T09:57:39Z"
}
```

- `sub`: User ID (matches `id`).
- `iss`: Configured `BaseURL` or `JWT.Issuer`.
- `aud`: Configured `BaseURL` or `JWT.Audience`.
- `exp`: Epoch seconds when the token expires (default: 15 minutes from issue).
- `iat`: Epoch seconds when the token was issued.
- Additional user profile fields: `name`, `email`, `emailVerified`, `image`.
