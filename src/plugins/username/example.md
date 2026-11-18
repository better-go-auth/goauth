# Username plugin

Lets users sign in with a username as well as their email. It is the Go version of better-auth's
`username()` plugin and is compatible with the better-auth `usernameClient()` plugin.

Runnable example: [src/example/username](../../example/username/main.go)

```sh
go run ./src/example/username     # server on http://localhost:8080, OpenAPI docs at /docs
go test ./src/example/username    # the flow below, end to end
```

## Setup

```go
import (
	"github.com/better-go-auth/goauth/src/plugins/username"
	usernameconfig "github.com/better-go-auth/goauth/src/plugins/username/config"
)

usernamePlugin := username.New(usernameconfig.UsernameConfig{
	MinUsernameLength: 3,  // default 3
	MaxUsernameLength: 20, // default 30
})

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: "http://localhost:8080"},
	Plugins:    []plugin.Plugin{usernamePlugin},
})
```

The plugin adds the nullable, unique `username` and `displayUsername` columns to the user table. The
migration runs during `SetupGoAuth`.

## Options

| Field | Default | Meaning |
|---|---|---|
| `MinUsernameLength` / `MaxUsernameLength` | 3 / 30 | Length bounds, checked on sign-up, update-user and sign-in |
| `UsernameValidator` | `^[a-zA-Z0-9_.]+$` | Replaces the character check |
| `DisplayUsernameValidator` | none | Checks `displayUsername` |
| `UsernameNormalization` | lowercase | How usernames are stored and looked up |
| `DisableUsernameNormalization` | false | Store usernames exactly as sent |
| `DisplayUsernameNormalization` | none | Normalizes `displayUsername` |
| `ValidationOrder` | pre-normalization | Whether validators see the raw value or the normalized one |

Each field also has a functional option, for example `username.WithMinUsernameLength(5)` or
`username.WithoutUsernameNormalization()`.

## Endpoints (under `/api/auth`)

| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/sign-up/email` | `email`, `password`, `name`, `username?`, `displayUsername?` | Core route. The plugin validates and stores the username |
| POST | `/sign-in/username` | `username`, `password`, `rememberMe?` | Sets the session cookie, like `/sign-in/email` |
| POST | `/is-username-available` | `username` | `{ "available": bool }` |
| POST | `/update-user` | `username?`, `displayUsername?` | Core route. The plugin checks the new username |

If only one of `username` and `displayUsername` is sent, the other is copied from it, as in better-auth.

## Flow

```sh
# 1. sign up with a username (stored as "alice_01"; displayUsername keeps "Alice_01")
curl -c jar -H 'Origin: http://localhost:8080' -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"Password123!","name":"Alice","username":"Alice_01"}' \
  http://localhost:8080/api/auth/sign-up/email

# 2. sign in with the username (any case) instead of the email
curl -c jar -H 'Origin: http://localhost:8080' -H 'Content-Type: application/json' \
  -d '{"username":"ALICE_01","password":"Password123!"}' \
  http://localhost:8080/api/auth/sign-in/username

# 3. call a protected route of your own with the session cookie
curl -b jar http://localhost:8080/api/example/me
```

## Errors

| Code | When |
|---|---|
| `USERNAME_IS_ALREADY_TAKEN` | Sign-up or update with a username another user has |
| `USERNAME_TOO_SHORT` / `USERNAME_TOO_LONG` | Outside the length bounds |
| `INVALID_USERNAME` | The validator rejected it |
| `INVALID_USERNAME_OR_PASSWORD` | Sign-in failed (401). The same error for an unknown user and a wrong password |

## Protecting your own routes

This applies to every plugin. Add goauth's `Authenticate` middleware, then read the session from the
context:

```go
huma.Register(api, huma.Operation{
	Method: http.MethodGet, Path: "/api/example/me",
	Middlewares: huma.Middlewares{auth.MiddlewareInt().Authenticate()},
}, func(ctx context.Context, _ *struct{}) (*Out, error) {
	s, _ := authenticator.SessionFromContext(ctx) // user ID, role, session ID, active organization
	u, err := auth.Repositories().FindUserByID(ctx, s.Session.UserID)
	...
})
```

`SessionFromContext` only holds what the session carries: IDs, the role and the active organization.
To get the email or other user fields, load the user with `FindUserByID`.
