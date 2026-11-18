# Have I Been Pwned plugin

Refuses passwords that appear in known data breaches. It is the Go version of better-auth's `haveIBeenPwned()`
plugin. Before an endpoint hashes a new password, the plugin looks the password up in the
[Pwned Passwords](https://haveibeenpwned.com/API/v3#PwnedPasswords) range API with k-anonymity: only the first
five characters of the password's SHA-1 hash leave the server.

Runnable example: [src/example/haveibeenpwned](../../example/haveibeenpwned/main.go)

```sh
go run ./src/example/haveibeenpwned    # server on http://localhost:8080 (real range API)
go test ./src/example/haveibeenpwned   # the flow below, against a fake range API
```

## Setup

```go
import (
	"github.com/better-go-auth/goauth/src/plugins/haveibeenpwned"
	hibpconfig "github.com/better-go-auth/goauth/src/plugins/haveibeenpwned/config"
)

hibpPlugin := haveibeenpwned.New(hibpconfig.HaveIBeenPwnedConfig{
	CustomPasswordCompromisedMessage: "Please choose a password that has not been leaked.",
})

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: "http://localhost:8080"},
	Plugins:    []plugin.Plugin{hibpPlugin},
})
```

The plugin has no routes, no tables and no client plugin.

## Options

| Field | Default | Meaning |
|---|---|---|
| `Paths` | `/sign-up/email`, `/change-password`, `/reset-password` | Endpoints whose new passwords are checked |
| `CustomPasswordCompromisedMessage` | better-auth's message | Message of `PASSWORD_COMPROMISED` |
| `Enabled` | true | `false` turns the check off |
| `APIURL` | `https://api.pwnedpasswords.com/range/` | Range API base URL (the prefix is appended) |
| `HTTPClient` | 30 s timeout | Client for the range API |

Any endpoint that hashes a new password can be listed in `Paths`, for example `/email-otp/reset-password`,
`/phone-number/reset-password` or `/admin/set-user-password`. Sign-in never hashes a new password, except the
timing-safe dummy hash for unknown users, which is checked when you list the sign-in path (better-auth does the
same).

## Flow

```sh
curl -i -X POST localhost:8080/api/auth/sign-up/email -H 'Content-Type: application/json' \
  -d '{"email":"a@example.com","password":"password123","name":"A"}'
# 400 {"code":"PASSWORD_COMPROMISED","message":"The password you entered has been compromised. Please choose a different password."}
```

## Errors

| Status | Code | Message |
|---|---|---|
| 400 | `PASSWORD_COMPROMISED` | The password you entered has been compromised. Please choose a different password. |
| 500 | `INTERNAL_SERVER_ERROR` | Failed to check password. Status: `<status>` (the range API answered an error) |
| 500 | `INTERNAL_SERVER_ERROR` | Failed to check password. Please try again later. (the range API could not be reached) |

## Notes

- The request goes out with better-auth's headers: `Add-Padding: true` and
  `User-Agent: BetterAuth Password Checker`.
- The check runs where better-auth's wrapped `ctx.password.hash` runs, so the order of errors is the same:
  length checks and an invalid reset token come first; change-password checks the new password before the
  current one. A rejected reset-password keeps the reset token usable.
- goauth runs it as a password-hash hook (`HookRegistry.OnPasswordHash`); every endpoint hashing a new password
  calls `authcrypto.Passwords.HashContext`, so plugins can add their own checks the same way.
