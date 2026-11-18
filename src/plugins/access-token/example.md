# Access-token plugin

goauth's own JWT flow for API and mobile clients. It is not a better-auth plugin and has no better-auth client.
`POST /login` returns a short-lived **access token** (an HS256 JWT) and a **refresh token**. The refresh token
is the session's own token, so every login is an ordinary better-auth session row. Clients send the access
token as `Authorization: Bearer <jwt>`, and `POST /refresh` gives them a new one.

Runnable example: [src/example/access-token](../../example/access-token/main.go)

```sh
go run ./src/example/access-token     # server on http://localhost:8080, OpenAPI docs at /docs
go test ./src/example/access-token    # the flow below, end to end
```

## Setup

```go
import (
	accesstoken "github.com/better-go-auth/goauth/src/plugins/access-token"
	accesstokenconfig "github.com/better-go-auth/goauth/src/plugins/access-token/config"
)

atPlugin := accesstoken.New(accesstokenconfig.AccessTokenConfig{
	Session: accesstokenconfig.SessionGoAuth{
		JWT: accesstokenconfig.SessionJWT{
			AccessSecret:    os.Getenv("JWT_ACCESS_SECRET"), // "" = derived from AuthConfig.Secret
			AccessExpiresIn: 15 * time.Minute,
		},
	},
})

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn: db,
	AuthConfig: config.AuthConfig{
		BaseURL: "http://localhost:8080",
		// POST /signup sends a verification code and fails when no sender is set
		EmailVerification: config.EmailVerification{
			GoAuth: config.EmailVerificationGoAuth{CodeSender: mySender}, // SendVerificationCode(to, code string) error
		},
	},
	Plugins: []plugin.Plugin{atPlugin},
})
```

The plugin adds no tables. It uses the core user, account, session and verification tables.

### Protecting routes with the access token

The access-token middleware is **not** global by default. Add it to each route that should accept access
tokens, before goauth's `Authenticate`:

```go
huma.Register(api, huma.Operation{
	Method: http.MethodGet, Path: "/api/example/jwt/me",
	Middlewares: huma.Middlewares{atPlugin.AuthMiddleware(), auth.MiddlewareInt().Authenticate()},
}, func(ctx context.Context, _ *struct{}) (*Out, error) {
	s, _ := authenticator.SessionFromContext(ctx) // same session data as with a cookie
	...
})
```

`AuthMiddleware` verifies the JWT and loads the live session behind it, so a revoked session is rejected
before its token expires. The route still accepts the better-auth session cookie.

The plugin also has two more helpers:

- `RequireRefreshToken()` answers 401 when the bearer token is a JWT, on routes that only take refresh tokens.
- `HTTPMiddleware()` is a plain `net/http` version of the middleware. It only checks the JWT's signature,
  not whether the session is still alive.

To accept access tokens on every route, including the core `/api/auth/*` endpoints such as `/get-session`,
set `AutoRegisterMiddleware: true`. The core `/sign-out` route accepts them either way (see [Logout](#logout)).

## Options

| Field | Default | Meaning |
|---|---|---|
| `Session.JWT.AccessSecret` | key derived from `AuthConfig.Secret` | HS256 key of the access tokens |
| `Session.JWT.AccessExpiresIn` | 15m | Access token lifetime |
| `Session.JWT.RotateSessionToken` | off | Issue a new refresh token on every `/refresh` |
| `Session.SingleSession` / `Session.UpdatableFields` | from `AuthConfig.Session.GoAuth` | Core session options |
| `AutoRegisterMiddleware` | false | Install the middleware on every route |
| `RequireBearerTokenOps` | none | Operation IDs on which the middleware ignores access tokens |
| `RejectBlockedAccessTokens` | false | Answer 401 on those operations instead of ignoring the token |

The refresh token lives as long as the session (`AuthConfig.Session.ExpiresIn`, 7 days by default). A call to
`/refresh` also extends the session, as better-auth does once `UpdateAge` has passed.

## Endpoints (under `/api/auth`)

| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/signup` | `fName`, `lName?`, `email`, `password`, `avatar?`, `country?` | 201. Creates the user and sends a verification code. No session is created |
| POST | `/login` | `info` (the email), `password`, `device_token?` | 201. Sets the `access-token` and `refresh-token` cookies |
| POST | `/refresh` | `token` (the refresh token) | 201. Same body and cookies as `/login` |

Responses are wrapped in goauth's legacy envelope:

```json
{ "body": { "user": {...}, "token": "<access jwt>", "redirect": false,
            "authTokens": { "access_token": "<jwt>", "refresh_token": "<session token>" } },
  "status": 201, "code": "SUCCESS", "message": "success" }
```

`/signup` validates its body like core `/sign-up/email`:

- `email` must be a bare address (`a@b.co`; not `Bob <a@b.co>`). It is stored lower-cased.
- `password` must be `EmailAndPassword.MinPasswordLength`..`MaxPasswordLength` characters (default 8..128).
- `fName` is required (at least 2 characters). `lName`, `avatar` and `country` are optional. Without
  `avatar`, the user's image is stored as `NULL`.

## Logout

Access-token clients log out through the **core** `POST /api/auth/sign-out` route. The plugin has no logout
route of its own. On that route, the plugin always runs a small middleware, whatever `AutoRegisterMiddleware`
says. It finds the session from the first of these that the request carries:

1. `Authorization: Bearer <access token>` (the JWT is verified and its session must still be alive)
2. `Authorization: Bearer <refresh token>`
3. the `refresh-token` cookie
4. the `access-token` cookie

Core sign-out then revokes that session. Its refresh token stops working, and its access tokens are
blacklisted until they expire. When the request carried access-token credentials, the response also
expires the `access-token` and `refresh-token` cookies, next to the usual better-auth cookies. Requests
that send cookies are browser requests, so core checks their `Origin` as on every sign-out. Bearer
requests without an `Origin` header skip that check.

Revoking the session any other way, for example with `/revoke-session`, also blacklists its access tokens.
From Go, `atPlugin.AuthService().Logout(ctx, refreshToken)` does the same.

## Flow

```sh
# 1. sign up (the verification code is printed in the example's log; lName is optional)
curl -H 'Content-Type: application/json' \
  -d '{"fName":"Alice","lName":"Doe","email":"alice@example.com","password":"Password123!"}' \
  http://localhost:8080/api/auth/signup

# 2. log in: keep body.authTokens.access_token and body.authTokens.refresh_token
curl -H 'Content-Type: application/json' \
  -d '{"info":"alice@example.com","password":"Password123!"}' \
  http://localhost:8080/api/auth/login

# 3. call a route protected by AuthMiddleware with the access token
curl -H "Authorization: Bearer $ACCESS" http://localhost:8080/api/example/jwt/me

# 4. when it expires, trade the refresh token for a new access token
curl -H 'Content-Type: application/json' -d "{\"token\":\"$REFRESH\"}" \
  http://localhost:8080/api/auth/refresh

# 5. log out through the core sign-out route (Bearer $REFRESH works too): both tokens stop working
curl -X POST -H "Authorization: Bearer $ACCESS" http://localhost:8080/api/auth/sign-out
```

## Errors

These routes use goauth's generic codes, not better-auth's:

| Status / code | When |
|---|---|
| 401 `UNAUTHORIZED` "Invalid email or password" | `/login` with a wrong password or an unknown email |
| 401 `UNAUTHORIZED` "Invalid token" | `/refresh` with an unknown, expired or revoked refresh token, or with an access token |
| 401 `UNAUTHORIZED` "Unauthorized" | A protected route with a missing, invalid, expired or revoked access token |
| 401 "access token not allowed on refresh-token-only route" | A JWT sent to a `RequireRefreshToken()` route |
| 400 `VALIDATION_ERROR` | A required body field is missing (`fName`, `email`, `password`), `fName` is shorter than 2 characters, or `email` is not a bare address |
| 400 `BAD_REQUEST` "Password too short" / "Password too long" | `/signup` password outside `MinPasswordLength`..`MaxPasswordLength` |

## Notes

- `/signup` does not stop duplicate emails. Like better-auth, it answers success with a made-up user, so
  attackers cannot use it to find out which emails are registered.
- `/login` follows the core rules: bans, `RequireEmailVerification` and password rehashing.
