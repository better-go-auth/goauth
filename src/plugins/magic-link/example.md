# Magic link plugin

Passwordless sign-in through a one-time link sent by email. Opening the link signs the user in, and
signs them up if they are new. It is the Go version of better-auth's `magicLink()` plugin and works with
the better-auth `magicLinkClient()` plugin.

Runnable example: [src/example/magic-link](../../example/magic-link/main.go)

```sh
go run ./src/example/magic-link     # server on http://localhost:8080. Links are printed to the log
go test ./src/example/magic-link    # runs the flow below end to end
```

## Setup

```go
import (
	magiclink "github.com/better-go-auth/goauth/src/plugins/magic-link"
	magiclinkconfig "github.com/better-go-auth/goauth/src/plugins/magic-link/config"
)

linkPlugin := magiclink.New(magiclinkconfig.MagicLinkConfig{
	// required: deliver data.URL (e.g. by email)
	SendMagicLink: func(data magiclinkconfig.SendMagicLinkData, r *http.Request) error {
		return mailer.Send(data.Email, "Sign in", data.URL)
	},
	ExpiresIn:  10 * time.Minute,
	StoreToken: magiclinkconfig.StoreTokenConfig{Mode: magiclinkconfig.StoreTokenHashed},
})

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: "http://localhost:8080"},
	Plugins:    []plugin.Plugin{linkPlugin},
})
```

The link is `<BaseURL>/api/auth/magic-link/verify?token=...&callbackURL=...`, so `BaseURL` must be the
public URL of the auth server. The plugin has no tables of its own. Tokens are stored in the core
`verification` table with the value `{"email","name"}`.

## Options (`MagicLinkConfig`)

| Field | Default | Meaning |
|---|---|---|
| `SendMagicLink` | none (required) | Delivers the link. `data` has `Email`, `URL`, `Token` and the request's `Metadata`. Setup fails without it |
| `ExpiresIn` | 5 min | How long a link is valid |
| `DisableSignUp` | false | Verify won't create users. Unknown addresses are redirected with `?error=new_user_signup_disabled` |
| `GenerateToken` | 32 random letters | Custom token generator `func(email string) string` |
| `StoreToken` | `{Mode: "plain"}` | `"hashed"` stores base64url(SHA-256(token)). `"custom-hasher"` with `Hash` uses your own hash |
| `RateLimit` | 5 requests / 60s | Per IP and path on both endpoints. Only enforced when `AuthConfig.RateLimit.Enabled` is true |

Functional options: `magiclink.WithSendMagicLink`, `WithExpiresIn`, `WithDisableSignUp`,
`WithGenerateToken`, `WithStoreToken`, `WithRateLimit`.

## Endpoints (under `/api/auth`)

| Method | Path | Input | Response |
|---|---|---|---|
| POST | `/sign-in/magic-link` | body: `email`, `name?`, `callbackURL?`, `newUserCallbackURL?`, `errorCallbackURL?`, `metadata?` | `{status: true}`. The link is sent |
| GET | `/magic-link/verify` | query: `token`, `callbackURL?`, `newUserCallbackURL?`, `errorCallbackURL?` | See below |

Verify uses the token once, creates the user if needed (`emailVerified: true`, `name` from the
request), marks an existing user's email as verified, and sets the session cookie. Then:

- With a `callbackURL` (the sent link always has one, `/` by default), it redirects with 302 to
  `callbackURL`. New users go to `newUserCallbackURL` if one was given. Relative targets are resolved
  against `BaseURL`.
- Without a `callbackURL`, it answers 200 with `{token, user, session}`. This is for API clients that
  call verify with just the token.
- If it fails, it redirects with 302 to `errorCallbackURL` (default: `callbackURL`, then `/`) with
  `?error=<code>`. No cookie is set.

## Flow

```sh
# 1. request a link (copy it from the server log)
curl -H 'Origin: http://localhost:8080' -H 'Content-Type: application/json' \
  -d '{"email":"linda@example.com","name":"Linda","callbackURL":"/dashboard","newUserCallbackURL":"/welcome"}' \
  http://localhost:8080/api/auth/sign-in/magic-link

# 2. open it: 302 to http://localhost:8080/welcome (first time) with the session cookie
curl -i -c jar 'http://localhost:8080/api/auth/magic-link/verify?token=...&callbackURL=%2Fdashboard&newUserCallbackURL=%2Fwelcome'

# 3. call a protected route of your own with the session cookie
curl -b jar http://localhost:8080/api/example/me
```

## Errors

Errors on `POST /sign-in/magic-link` (JSON):

| Code | Status | When |
|---|---|---|
| `INVALID_EMAIL` | 400 | The address fails better-auth's (zod) email check |
| `INVALID_CALLBACK_URL` / `INVALID_NEW_USER_CALLBACK_URL` / `INVALID_ERROR_CALLBACK_URL` | 403 | A redirect target is not on `BaseURL` or `TrustedOrigins` |

Errors on `GET /magic-link/verify` (a redirect to `errorCallbackURL?error=<code>`):

| Code | When |
|---|---|
| `INVALID_TOKEN` | Unknown, already used or expired token |
| `new_user_signup_disabled` | Unknown address with `DisableSignUp` |
| `failed_to_create_user` / `failed_to_create_session` | Database failure |

An untrusted redirect target on verify gives 403 `INVALID_CALLBACK_URL` (JSON). better-auth uses this
code for all three targets. Hook errors (for example the admin plugin's ban check) are returned as JSON
with their own code.

## Notes

- Links are single use, even if the click is retried. A second click lands on the error URL.
- Requesting a new link doesn't invalidate older ones. Each link expires on its own.
- Use `StoreTokenHashed` in production so a leaked `verification` table can't be used to sign in.
- To protect your own routes, see the "Protecting your own routes" section in
  [the username example](../username/example.md#protecting-your-own-routes).
