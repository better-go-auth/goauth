# Bearer plugin

Lets clients that can't keep cookies (mobile apps, CLIs, other servers) authenticate with
`Authorization: Bearer <token>`. Responses that set the session cookie also send its value in the
`set-auth-token` header. The client stores it and sends it back as a bearer token, and the plugin turns
the header back into the session cookie. Every goauth route and your own protected routes accept it. It
is the Go version of better-auth's `bearer()` plugin.

Runnable example: [src/example/bearer](../../example/bearer/main.go)

```sh
go run ./src/example/bearer     # server on http://localhost:8080, OpenAPI docs at /docs
go test ./src/example/bearer    # the flow below, end to end
```

## Setup

```go
import (
	"github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
)

bearerPlugin := bearer.New(bearerconfig.DefaultConfig()) // RequireSignature: true

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: "http://localhost:8080"},
	Plugins:    []plugin.Plugin{bearerPlugin},
})
```

The plugin has no routes and no tables. It is a Huma middleware that `SetupGoAuth` installs before the
core and plugin routes are mounted. Routes you register after `SetupGoAuth` are covered too.

## Options

| Field | Default | Meaning |
|---|---|---|
| `RequireSignature` | `true` (also when nil) | Accept only signed tokens `<session token>.<HMAC-SHA256 signature>`, which is the value of `set-auth-token`. With `false`, the raw session token (the `token` field of sign-in / sign-up) is accepted too |

Functional options: `bearer.WithRequireSignature(false)` and `bearer.WithConfig(cfg)`. The plugin logs a
warning at startup when signatures are not required.

## Headers

| Direction | Header | Meaning |
|---|---|---|
| Response | `set-auth-token` | The signed session token. Sent whenever the response sets the session cookie (sign-in, sign-up, ...) and listed in `Access-Control-Expose-Headers` |
| Request | `Authorization: Bearer <token>` | Used as the session cookie. A request that already has a session cookie keeps its cookie |

## Flow

```sh
# 1. sign in and read the set-auth-token header
curl -i -H 'Origin: http://localhost:8080' -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"Password123!"}' \
  http://localhost:8080/api/auth/sign-in/email
# set-auth-token: 5Kd...Xq.9wq...=   <- the whole value, signature included

# 2. call your own protected route and goauth's routes with it, no cookie
curl -H 'Authorization: Bearer 5Kd...Xq.9wq...=' http://localhost:8080/api/example/me
curl -H 'Authorization: Bearer 5Kd...Xq.9wq...=' http://localhost:8080/api/auth/get-session

# 3. sign out with it
curl -X POST -H 'Origin: http://localhost:8080' -H 'Content-Type: application/json' -d '{}' \
  -H 'Authorization: Bearer 5Kd...Xq.9wq...=' http://localhost:8080/api/auth/sign-out
```

## Errors

The plugin never answers by itself. A missing, unsigned (with `RequireSignature`) or badly signed token
is ignored, so the request is unauthenticated: protected routes answer 401 `UNAUTHORIZED`, and
`/get-session` returns `null`.

## Notes

- Signatures are accepted in standard or URL-safe base64, padded or not, and URL-encoded tokens
  (`%3D`) are decoded first.
- The bearer token is the session token. It lives as long as the session and is revoked with it. For
  short-lived, self-contained tokens that other services verify, use the [jwt plugin](../jwt/example.md).
- Keep `RequireSignature` on. Turning it off makes a leaked raw session token (for example from a
  database dump) enough to sign in.
