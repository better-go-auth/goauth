# Passkey plugin

Lets users sign in with a passkey (WebAuthn: Touch ID, Windows Hello, a phone or a security key)
instead of a password. It is the Go version of better-auth's `passkey()` plugin
(`@better-auth/passkey`) and is compatible with its `passkeyClient()`.

Runnable example: [src/example/passkey](../../example/passkey/main.go)

```sh
go run ./src/example/passkey     # server on http://localhost:8080, OpenAPI docs at /docs
go test ./src/example/passkey    # the flow below, end to end, with a software authenticator
```

## Setup

```go
import (
	"github.com/better-go-auth/goauth/src/plugins/passkey"
	pkconfig "github.com/better-go-auth/goauth/src/plugins/passkey/config"
)

passkeyPlugin := passkey.New(pkconfig.PasskeyConfig{
	RPID:   "example.com",                 // the domain passkeys are bound to
	RPName: "My App",                      // shown by the authenticator
	Origin: []string{"https://example.com"}, // the page origin(s) the browser reports
})

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: "https://example.com"},
	Plugins:    []plugin.Plugin{passkeyPlugin},
})
```

The plugin creates better-auth's `passkey` table. The migration runs during `SetupGoAuth`.

In the browser, use the better-auth client:

```ts
import { createAuthClient } from "better-auth/client";
import { passkeyClient } from "@better-auth/passkey/client";

const authClient = createAuthClient({ baseURL: "https://example.com", plugins: [passkeyClient()] });
await authClient.passkey.addPasskey({ name: "Laptop" }); // signed in: register
await authClient.signIn.passkey();                       // later: sign in
```

## Options

| Field | Default | Meaning |
|---|---|---|
| `RPID` | host of `BaseURL` (else `localhost`) | Relying party ID |
| `RPName` | `AppName` | Relying party name |
| `Origin` | the request's `Origin` header | Expected origin(s) of WebAuthn responses |
| `AuthenticatorSelection` | residentKey and userVerification `preferred` | `AuthenticatorAttachment`, `ResidentKey`, `UserVerification` |
| `Registration.RequireSession` | true | Set `pkconfig.Bool(false)` for passkey-first sign-up, with `ResolveUser` returning the user |
| `Registration.AfterVerification` | nil | Runs before the passkey is stored. It can rename it or move it to another user |
| `Registration.Extensions` / `ExtensionsFunc` | `credProps` | WebAuthn extensions in the registration options |
| `Authentication.AfterVerification` | nil | Runs after a verified assertion. An error aborts the sign-in |
| `Authentication.Extensions` / `ExtensionsFunc` | none | WebAuthn extensions in the authentication options |
| `Advanced.WebAuthnChallengeCookie` | `better-auth-passkey` | Name of the signed challenge cookie (prefixed like the other auth cookies) |

The functional options `passkey.WithRPID`, `WithRPName`, `WithOrigin`, `WithAuthenticatorSelection`
and `WithRepository` set the same values.

## Endpoints (under `/api/auth`)

| Method | Path | Needs | Body / query | Response |
|---|---|---|---|---|
| GET | `/passkey/generate-register-options` | fresh session | `?authenticatorAttachment=platform\|cross-platform&name=&context=` | `PublicKeyCredentialCreationOptionsJSON` + challenge cookie |
| POST | `/passkey/verify-registration` | fresh session | `response` (from `startRegistration`), `name?` | the stored passkey |
| GET | `/passkey/generate-authenticate-options` | none | | `PublicKeyCredentialRequestOptionsJSON` + challenge cookie. With a session, `allowCredentials` lists the user's passkeys |
| POST | `/passkey/verify-authentication` | none | `response` (from `startAuthentication`) | `{ session, user }` + session cookie |
| GET | `/passkey/list-user-passkeys` | session | | the user's passkeys |
| POST | `/passkey/update-passkey` | session | `id`, `name` | `{ passkey }` |
| POST | `/passkey/delete-passkey` | session | `id` | `{ status: true }` |

A fresh session is one younger than `Session.FreshAge` (default 1 day). Each challenge is valid for
5 minutes and can be used once.

## Flow

WebAuthn needs a browser (or the software authenticator in
[main_test.go](../../example/passkey/main_test.go)), so only the plain HTTP steps are shown with curl.

```sh
H='-H Origin:http://localhost:8080 -H Content-Type:application/json'

# 1. sign in, then fetch registration options; pass them to navigator.credentials.create
#    (startRegistration) and POST its result: {"response": <RegistrationResponseJSON>, "name": "Laptop"}
curl -c jar -b jar $H -d '{"email":"alice@example.com","password":"Password123!","name":"Alice"}' \
  http://localhost:8080/api/auth/sign-up/email
curl -c jar -b jar http://localhost:8080/api/auth/passkey/generate-register-options
#    ... POST /api/auth/passkey/verify-registration with the same jar

# 2. list the passkeys
curl -b jar http://localhost:8080/api/auth/passkey/list-user-passkeys

# 3. sign in from another browser: options → navigator.credentials.get (startAuthentication) →
#    POST {"response": <AuthenticationResponseJSON>} to /api/auth/passkey/verify-authentication
curl -c jar2 -b jar2 http://localhost:8080/api/auth/passkey/generate-authenticate-options

# 4. the session cookie from verify-authentication opens your protected routes
curl -b jar2 http://localhost:8080/api/example/me
```

## Errors

| Code | Status | When |
|---|---|---|
| `CHALLENGE_NOT_FOUND` | 400 | Missing, expired or already used challenge cookie |
| `FAILED_TO_VERIFY_REGISTRATION` | 400 / 500 | The registration response did not verify (wrong origin, rpID, challenge, ...) |
| `YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY` | 401 | Registration started for another user, or `update-passkey` of another user's passkey |
| `PASSKEY_NOT_FOUND` | 401 / 404 | Unknown credential on `verify-authentication` (401). Unknown `id` on update/delete (404) |
| `AUTHENTICATION_FAILED` | 400 / 401 | The assertion did not verify (bad signature: 401) |
| `UNAUTHORIZED` | 401 | `delete-passkey` of another user's passkey, or no session |
| `SESSION_NOT_FRESH` | 403 | Registration with a session older than `Session.FreshAge` |
| `BAD_REQUEST` | 400 | `verify-authentication` with no `Origin` header and no `Origin` option (`origin missing`), or `delete-passkey` without `id` |

## Notes

- The signature counter is stored on every sign-in. Authenticators that always report 0 keep working.
- `RPID` must be the page's domain or a parent of it. During local development use `localhost`.
- Deleting a user deletes their passkeys.
