# One-time-token plugin

Lets a signed-in client hand its session to another client. The first client asks for a short-lived,
single-use token. The second client (a mobile app, another domain, a desktop app opened from the
browser) exchanges it for the same session. It is the Go version of better-auth's `oneTimeToken()`
plugin and is compatible with the better-auth `oneTimeTokenClient()` plugin.

Runnable example: [src/example/one-time-token](../../example/one-time-token/main.go)

```sh
go run ./src/example/one-time-token     # server on http://localhost:8080, OpenAPI docs at /docs
go test ./src/example/one-time-token    # the flow below, end to end
```

## Setup

```go
import (
	onetimetoken "github.com/better-go-auth/goauth/src/plugins/one-time-token"
	ottconfig "github.com/better-go-auth/goauth/src/plugins/one-time-token/config"
)

ottPlugin := onetimetoken.New(ottconfig.OneTimeTokenConfig{
	ExpiresIn:                2 * time.Minute, // default 3 minutes
	StoreToken:               ottconfig.StoreTokenConfig{Mode: ottconfig.StoreTokenHashed},
	SetOttHeaderOnNewSession: true,
})

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: "http://localhost:8080"},
	Plugins:    []plugin.Plugin{ottPlugin},
})
```

Tokens are stored in the core verification table under `one-time-token:<token>`, so the plugin has no
migration.

## Options

| Field | Default | Meaning |
|---|---|---|
| `ExpiresIn` | 3 minutes | How long a token stays valid |
| `DisableClientRequest` | false | Turns off `/one-time-token/generate`. Create tokens on the server with `plugin.Service().GenerateToken(ctx, session)` |
| `DisableSetSessionCookie` | false | `/one-time-token/verify` returns the session but sets no cookie |
| `GenerateToken` | 32 random characters (`a-z A-Z 0-9 - _`) | Custom token generator |
| `StoreToken` | `plain` | `StoreTokenHashed` stores base64url(SHA-256(token)). `StoreTokenCustom` with `Hash` uses your hasher |
| `SetOttHeaderOnNewSession` | false | Every response that sets a new session cookie also carries a fresh token in the `set-ott` header (exposed through `Access-Control-Expose-Headers`) |

Each field also has a functional option, for example `onetimetoken.WithExpiresIn(time.Minute)` or
`onetimetoken.WithSetOttHeaderOnNewSession(true)`.

## Endpoints (under `/api/auth`)

| Method | Path | Body | Notes |
|---|---|---|---|
| GET | `/one-time-token/generate` | none | Needs a session. Returns `{ token }` for the current session |
| POST | `/one-time-token/verify` | `token` | Public. Consumes the token and returns `{ session, user }`, and sets the session cookie unless `DisableSetSessionCookie` |

## Flow

```sh
# 1. sign in (the first client keeps the cookie)
curl -c jar -H 'Origin: http://localhost:8080' -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"Password123!"}' \
  http://localhost:8080/api/auth/sign-in/email

# 2. the first client asks for a one-time token
curl -b jar http://localhost:8080/api/auth/one-time-token/generate
# {"token":"q3V..."}

# 3. a second client, with no cookies, exchanges it for the same session
curl -c jar2 -H 'Origin: http://localhost:8080' -H 'Content-Type: application/json' \
  -d '{"token":"q3V..."}' http://localhost:8080/api/auth/one-time-token/verify
curl -b jar2 http://localhost:8080/api/example/me

# 4. the same token again: 400 INVALID_TOKEN
```

## Errors

All errors are 400. better-auth sends only a message for them, and goauth adds a code derived from it.

| Code | When |
|---|---|
| `INVALID_TOKEN` | Unknown token, or a token that was already used |
| `TOKEN_EXPIRED` | The token is older than `ExpiresIn`. It is deleted, so a retry gives `INVALID_TOKEN` |
| `SESSION_NOT_FOUND` | The session the token was created for no longer exists (for example after sign-out) |
| `SESSION_EXPIRED` | That session has expired |
| `CLIENT_REQUESTS_ARE_DISABLED` | `/one-time-token/generate` with `DisableClientRequest` |

`/one-time-token/generate` without a session answers 401 `UNAUTHORIZED`.

## Notes

- A token is consumed atomically: two concurrent verify calls with the same token can't both succeed.
- The token stands for the existing session, not a copy. Signing out on either client ends it for both.
