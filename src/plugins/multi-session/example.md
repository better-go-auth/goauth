# Multi-session plugin

Lets one browser be signed in as several users at once and switch between them, like account
switching in Gmail. It is the Go version of better-auth's `multiSession()` plugin and is compatible
with the better-auth `multiSessionClient()` plugin.

Runnable example: [src/example/multi-session](../../example/multi-session/main.go)

```sh
go run ./src/example/multi-session     # server on http://localhost:8080, OpenAPI docs at /docs
go test ./src/example/multi-session    # the flow below, end to end
```

## Setup

```go
import (
	multisession "github.com/better-go-auth/goauth/src/plugins/multi-session"
	msconfig "github.com/better-go-auth/goauth/src/plugins/multi-session/config"
)

multiSessionPlugin := multisession.New(msconfig.MultiSessionConfig{
	MaximumSessions: 3, // default 5
})

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: "http://localhost:8080"},
	Plugins:    []plugin.Plugin{multiSessionPlugin},
})
```

The plugin has no tables. Every response that sets a new session cookie (sign-up, sign-in by any
method, a session created by another plugin) also sets a signed
`better-auth.session_token_multi-<token>` cookie, so the browser remembers each of its sessions. The
normal `session_token` cookie is the active session, the one `get-session` and your own protected
routes see.

## Options

| Field | Default | Meaning |
|---|---|---|
| `MaximumSessions` | 5 | Sessions one browser can hold. A sign-in beyond it still becomes active, but is not added to the list |
| `GoAuth.StrictDeviceCookie` | false | goauth only. `set-active` and `revoke` require the browser's device cookie to hold exactly the requested token. better-auth only checks that a validly signed cookie exists under the token's lowercased name, so two tokens differing only in letter case share a cookie |

`multisession.WithMaximumSessions(n)` sets `MaximumSessions` too.

## Endpoints (under `/api/auth`)

| Method | Path | Needs | Body | Response |
|---|---|---|---|---|
| GET | `/multi-session/list-device-sessions` | none | | `[{ session, user }]`, the browser's live sessions, one per user |
| POST | `/multi-session/set-active` | a device cookie for the token | `sessionToken` | `{ session, user }` + the new `session_token` cookie |
| POST | `/multi-session/revoke` | session + a device cookie for the token | `sessionToken` | `{ status: true }` |

Revoking the active session switches the browser to its next live session, or signs it out when
there is none. Revoking another session leaves the active one alone. A sign-in as a user the browser
already holds replaces that user's old session. `POST /sign-out` revokes every session of the browser.

## Flow

```sh
H='-H Origin:http://localhost:8080 -H Content-Type:application/json'

# 1. two users sign in in the same browser (cookie jar); the last one is active
curl -c jar -b jar $H -d '{"email":"alice@example.com","password":"Password123!","name":"Alice"}' \
  http://localhost:8080/api/auth/sign-up/email
curl -c jar -b jar $H -d '{"email":"bob@example.com","password":"Password123!","name":"Bob"}' \
  http://localhost:8080/api/auth/sign-up/email
curl -b jar http://localhost:8080/api/example/me                     # bob

# 2. list the browser's sessions and switch to Alice's
curl -b jar http://localhost:8080/api/auth/multi-session/list-device-sessions
curl -c jar -b jar $H -d '{"sessionToken":"<alice session.token>"}' \
  http://localhost:8080/api/auth/multi-session/set-active
curl -b jar http://localhost:8080/api/example/me                     # alice

# 3. revoke one session (the active one: the browser falls back to Bob)
curl -c jar -b jar $H -d '{"sessionToken":"<alice session.token>"}' \
  http://localhost:8080/api/auth/multi-session/revoke
```

## Errors

| Code | Status | When |
|---|---|---|
| `INVALID_SESSION_TOKEN` | 401 | The browser has no device cookie for `sessionToken`, or that session expired or was revoked (its device cookie is then cleared) |
| `UNAUTHORIZED` | 401 | `revoke` without a session |
