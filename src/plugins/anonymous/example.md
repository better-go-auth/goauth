# Anonymous plugin

Gives visitors a real session without an email or password. When the anonymous user later signs up or
signs in, the plugin calls `OnLinkAccount` so the app can move the visitor's data to the real account,
then deletes the anonymous user. It is the Go version of better-auth's `anonymous()` plugin and is
compatible with the better-auth `anonymousClient()` plugin.

Runnable example: [src/example/anonymous](../../example/anonymous/main.go)

```sh
go run ./src/example/anonymous     # server on http://localhost:8080, OpenAPI docs at /docs
go test ./src/example/anonymous    # the flow below, end to end
```

## Setup

```go
import (
	"github.com/better-go-auth/goauth/src/plugins/anonymous"
	anonconfig "github.com/better-go-auth/goauth/src/plugins/anonymous/config"
)

anonPlugin := anonymous.New(anonconfig.AnonymousConfig{
	EmailDomainName: "guest.example.com", // temp-<id>@guest.example.com
	GenerateName:    func(context.Context, *http.Request) string { return "Guest" },
	OnLinkAccount: func(ctx context.Context, data anonconfig.LinkAccountData) error {
		// move the visitor's data: data.AnonymousUser.User.ID -> data.NewUser.User.ID
		return nil
	},
})

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: "http://localhost:8080"},
	Plugins:    []plugin.Plugin{anonPlugin},
})
```

`isAnonymous` is a column of the core user table, so the plugin has no migration. Installing the plugin
adds `isAnonymous` to every user object in responses. Clients can't set it through `/update-user`.

## Options

| Field | Default | Meaning |
|---|---|---|
| `EmailDomainName` | none | Anonymous emails become `temp-<id>@<domain>`. Without it they are `temp@<id>.com` |
| `GenerateName` | `"Anonymous"` | Name of new anonymous users |
| `GenerateRandomEmail` | none | Replaces the generated email. It must return a bare address, or sign-in fails with `INVALID_EMAIL_FORMAT` |
| `OnLinkAccount` | none | Runs when a request with an anonymous session creates a session for another user. A returned error becomes the response |
| `DisableDeleteAnonymousUser` | false | Keep the anonymous user after linking, and turn off `/delete-anonymous-user` |

Each field also has a functional option, for example `anonymous.WithOnLinkAccount(fn)` or
`anonymous.WithDisableDeleteAnonymousUser(true)`.

## Endpoints (under `/api/auth`)

| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/sign-in/anonymous` | none | Creates the user and sets the session cookie. Returns `{ token, user }` with `user.isAnonymous: true` |
| POST | `/delete-anonymous-user` | none | Needs a fresh anonymous session. Deletes the user and its sessions and clears the cookie. Returns `{ success: true }` |

Linking runs after any endpoint whose path starts with `/sign-in`, `/sign-up`, `/callback`,
`/oauth2/callback`, `/magic-link/verify`, `/email-otp/verify-email`, `/one-tap/callback`,
`/passkey/verify-authentication`, `/phone-number/verify` or `/verify-email`. It only runs when the request
still carries the anonymous session cookie. The order is: `OnLinkAccount`, then the anonymous user is
deleted. Deletion is skipped when `DisableDeleteAnonymousUser` is set or the new user is the same user or
is also anonymous.

## Flow

```sh
# 1. sign in anonymously (the cookie jar now holds an anonymous session)
curl -c jar -b jar -X POST -H 'Origin: http://localhost:8080' \
  http://localhost:8080/api/auth/sign-in/anonymous

# 2. the session works on protected routes; the example also stores notes per user
curl -b jar http://localhost:8080/api/example/me
curl -c jar -b jar -H 'Origin: http://localhost:8080' -H 'Content-Type: application/json' \
  -d '{"text":"buy milk"}' http://localhost:8080/api/example/notes

# 3. sign up with the anonymous cookie still sent: OnLinkAccount moves the notes,
#    the anonymous user is deleted and the jar gets the new (non-anonymous) session
curl -c jar -b jar -H 'Origin: http://localhost:8080' -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"Password123!","name":"Alice"}' \
  http://localhost:8080/api/auth/sign-up/email

curl -b jar http://localhost:8080/api/auth/get-session   # user.isAnonymous is false
curl -b jar http://localhost:8080/api/example/notes      # ["buy milk"]
```

## Errors

| Code | When |
|---|---|
| `ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY` | `/sign-in/anonymous` with an anonymous session (400) |
| `INVALID_EMAIL_FORMAT` | `GenerateRandomEmail` returned something that is not an email (400) |
| `FAILED_TO_CREATE_USER` / `COULD_NOT_CREATE_SESSION` | The user or session could not be created (500 / 400) |
| `USER_IS_NOT_ANONYMOUS` | `/delete-anonymous-user` with a normal user's session (403) |
| `DELETE_ANONYMOUS_USER_DISABLED` | `/delete-anonymous-user` with `DisableDeleteAnonymousUser` (400) |
| `SESSION_NOT_FRESH` | `/delete-anonymous-user` with a session older than `Session.FreshAge` (403) |
| `FAILED_TO_DELETE_ANONYMOUS_USER` / `FAILED_TO_DELETE_ANONYMOUS_USER_SESSIONS` | Deletion failed (500) |

## Notes

- An error from `OnLinkAccount` is sent as the response, but the new session has already been created, as
  in better-auth. If deleting the anonymous user fails after linking, the error is logged and the sign-in
  still succeeds.
- `/sign-in/anonymous` gets the global limiter's `/sign-in` special rule (3 requests per 10 seconds) while
  `AuthConfig.RateLimit` is enabled (default: production only).
- With `User.GoAuth.SoftDelete` on, deleted anonymous users are soft-deleted like any other user.
