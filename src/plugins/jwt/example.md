# JWT plugin

Issues short-lived JWTs for goauth sessions and publishes the public keys as a JWKS, so other services
can verify a user without calling goauth or sharing a secret. It is the Go version of better-auth's
`jwt()` plugin and is compatible with the better-auth `jwtClient()` plugin. Tokens are signed with
EdDSA (Ed25519) by default; ES256, ES512, PS256 and RS256 are also supported (see
[Algorithms](#algorithms)).

Runnable example: [src/example/jwt](../../example/jwt/main.go). It also contains `JWKSVerifier`, the
code an external service runs to verify the tokens.

```sh
go run ./src/example/jwt     # server on http://localhost:8080, OpenAPI docs at /docs
go test ./src/example/jwt    # the flow below, end to end
```

## Setup

```go
import (
	"github.com/better-go-auth/goauth/src/models/dtos"
	jwtplugin "github.com/better-go-auth/goauth/src/plugins/jwt"
	jwtconfig "github.com/better-go-auth/goauth/src/plugins/jwt/config"
)

jwtPlugin := jwtplugin.New(jwtconfig.JWTConfig{
	JWT: jwtconfig.JWTClaimConfig{
		Issuer:         "https://auth.example.com", // default: BaseURL
		Audience:       "https://api.example.com",  // default: BaseURL
		ExpirationTime: 10 * time.Minute,           // default: 15 minutes
		DefinePayload: func(session any) (map[string]any, error) {
			sw := session.(*dtos.SessionWithUser)
			return map[string]any{"email": sw.User.Email, "name": sw.User.Name}, nil
		},
	},
})

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: "http://localhost:8080"},
	Plugins:    []plugin.Plugin{jwtPlugin},
})
```

The plugin adds a `jwks` table for its key pairs, migrated during `SetupGoAuth`. The first key is created
on the first `/token` or `/jwks` call. Private keys are encrypted with the auth secret.

## Options

| Field | Default | Meaning |
|---|---|---|
| `JWT.Issuer` / `JWT.Audience` | `BaseURL` | The `iss` / `aud` claims |
| `JWT.ExpirationTime` | 15 minutes | Token lifetime (`exp - iat`) |
| `JWT.DefinePayload` | the user object | Returns the claims. The argument is a `*dtos.SessionWithUser`. It replaces the default claims (`id`, `name`, `email`, `emailVerified`, `image`, `createdAt`, `updatedAt` and, with the admin plugin, `role`). Returning nil is the same as an empty map |
| `JWT.GetSubject` | user ID | The `sub` claim, which is always added |
| `JWT.Sign` | none | Custom signer: receives the claims and returns the token, replacing the built-in key |
| `Jwks.JwksPath` | `/jwks` | Path of the key set |
| `Jwks.KeyPairConfig.Alg` | `EdDSA` | Signing algorithm of new keys: `EdDSA`, `ES256`, `ES512`, `PS256`, `RS256` |
| `Jwks.KeyPairConfig.Crv` | from `Alg` | `Ed25519` (EdDSA), `P-256` (ES256), `P-521` (ES512). Leave empty |
| `Jwks.KeyPairConfig.ModulusLength` | 2048 | RSA key size for `PS256` / `RS256` (minimum 2048) |
| `Jwks.RemoteURL` | none | Keys are published elsewhere. The local JWKS endpoint answers 404 |
| `Jwks.RotationInterval` | 0 (off) | A new key is created when the current one is older than this |
| `Jwks.GracePeriod` | 30 days | How long a rotated key stays in the JWKS |
| `Jwks.DisablePrivateKeyEncryption` | false | Store private keys unencrypted |
| `DisableSettingJwtHeader` | false | Don't send `set-auth-jwt` on `/get-session` |

Functional options include `jwtplugin.WithIssuer`, `WithAudience`, `WithExpirationTime`, `WithJwksPath`,
`WithDisableSettingJwtHeader` and `WithBasePath` (default: the core `AuthConfig.BasePath`).

## Algorithms

```go
jwtplugin.New(jwtconfig.JWTConfig{
	Jwks: jwtconfig.JwksConfig{
		KeyPairConfig: jwtconfig.KeyPairConfig{Alg: jwtconfig.AlgES256}, // or AlgRS256 + ModulusLength: 3072
	},
})
```

| `Alg` | Key | JWKS entry |
|---|---|---|
| `EdDSA` (default) | Ed25519 | `{ kty: "OKP", crv: "Ed25519", x }` |
| `ES256` | ECDSA P-256 | `{ kty: "EC", crv: "P-256", x, y }` |
| `ES512` | ECDSA P-521 | `{ kty: "EC", crv: "P-521", x, y }` |
| `PS256` | RSA-PSS, `ModulusLength` bits (default 2048) | `{ kty: "RSA", n, e }` |
| `RS256` | RSA PKCS#1 v1.5, `ModulusLength` bits (default 2048) | `{ kty: "RSA", n, e }` |

Every JWKS entry also has `kid`, `alg` and `use: "sig"`. An unsupported value (for example `ECDH-ES`,
which is a key-agreement algorithm, or a `Crv` that does not match `Alg`) makes `SetupGoAuth` fail.

Keys are stored like better-auth's (JWK JSON, private key encrypted with the auth secret). Tokens are
signed with the newest key of the configured algorithm, so changing `Alg` creates a new key on the next
token; older keys stay in the JWKS and their tokens keep verifying. Existing Ed25519 keys keep working.

## Endpoints

| Method | Path | Notes |
|---|---|---|
| GET | `/api/auth/token` | Needs a session (cookie, or `Authorization: Bearer` with the bearer plugin). Returns `{ token }` |
| GET | `/api/auth/get-session` | Core route. With a session, the response also has the `set-auth-jwt` header (listed in `Access-Control-Expose-Headers`) |
| GET | `/api/auth/jwks` and `/jwks` | Public. `{ keys: [{ kty: "OKP", crv: "Ed25519", alg: "EdDSA", use: "sig", kid, x }] }` (other members for EC / RSA keys, see [Algorithms](#algorithms)). Tokens name their key in the `kid` header |

better-auth's `POST /sign-jwt` and `POST /verify-jwt` are server-only (`auth.api.signJWT` /
`auth.api.verifyJWT`). goauth does not serve them over HTTP (both paths answer 404); call them from Go.

## Signing and verifying from Go

Sign arbitrary claims on the server, for example a token for an internal service, with the plugin you
passed to `SetupGoAuth` (or `auth.Plugin(jwtplugin.PluginID).(*jwtplugin.Plugin)`):

```go
tok, err := jwtPlugin.SignJWT(ctx, map[string]any{
	"sub":   "service:billing",
	"scope": "internal",
}, &jwtplugin.SignJWTOptions{ExpirationTime: 5 * time.Minute}) // opts may be nil

claims, err := jwtPlugin.VerifyJWT(ctx, tok, "") // "" = the configured issuer; err when invalid
```

- `SignJWT` fills in missing `iat`, `exp`, `iss` and `aud` from the configuration. `SignJWTOptions`
  overrides `Issuer`, `Audience` and `ExpirationTime` for that token (better-auth's `overrideOptions`).
  A nil payload is an empty one. The token is signed with the active key and verifies against the JWKS.
- `VerifyJWT` checks the signature (only the algorithm of the key named by `kid`), `exp`, `iss`, `aud`
  and that `sub` is present, and returns the claims.
- `jwtPlugin.Service()` returns the underlying `*services.JWTService` (`SignJWT`, `VerifyJWT`,
  `GetJWTToken`, `GetJWKS`, ...). Both are available after `SetupGoAuth`.

The example's `SignServiceToken` does this.

## Flow

```sh
# 1. sign in, then get a JWT for the session
curl -c jar -H 'Origin: http://localhost:8080' -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"Password123!"}' \
  http://localhost:8080/api/auth/sign-in/email
curl -b jar http://localhost:8080/api/auth/token
# {"token":"eyJhbGciOiJFZERTQSIsImtpZCI6Ii4uLiJ9..."}

# get-session hands one out too
curl -i -b jar http://localhost:8080/api/auth/get-session   # set-auth-jwt: eyJ...

# 2. another service fetches the public keys once and verifies tokens offline
curl http://localhost:8080/api/auth/jwks
```

The verifying service checks the signature with the key named by `kid`, the algorithm (`EdDSA`, or the
one you configured) and the
`iss`, `aud` and `exp` claims. With `github.com/golang-jwt/jwt/v5`, as in the example's `JWKSVerifier`:

```go
verifier := &JWKSVerifier{
	JWKSURL:  "http://localhost:8080/api/auth/jwks",
	Issuer:   "https://auth.example.com",
	Audience: "https://api.example.com",
}
claims, err := verifier.Verify(ctx, token) // claims["sub"] is the user ID
```

`JWKSVerifier` caches keys by `kid` and fetches the JWKS again when a token names an unknown key, so key
rotation needs no restart.

## Errors

| Status | When |
|---|---|
| 401 `UNAUTHORIZED` | `/token` without a session |
| 404 | `/jwks` with `Jwks.RemoteURL` set |

## Notes

- A JWT can't be revoked: it stays valid until `exp`, even after sign-out. Keep `ExpirationTime` short
  and fetch a new token when it expires.
- The JWT is not accepted by goauth's own session middleware. It is for other services. For cookie-less
  access to goauth itself, use the [bearer plugin](../bearer/example.md).
