# Last login method plugin

Remembers how a user last signed in, so a login page can show "Last used" next to the right button. It is the
Go version of better-auth's `lastLoginMethod()` plugin and works with the better-auth `lastLoginMethodClient()`
plugin.

Runnable example: [src/example/last-login-method](../../example/last-login-method/main.go)

```sh
go run ./src/example/last-login-method    # server on http://localhost:8080
go test ./src/example/last-login-method   # the flow below, end to end
```

## Setup

```go
import (
	lastloginmethod "github.com/better-go-auth/goauth/src/plugins/last-login-method"
	llmconfig "github.com/better-go-auth/goauth/src/plugins/last-login-method/config"
)

lastLogin := lastloginmethod.New(llmconfig.LastLoginMethodConfig{
	StoreInDatabase: true, // optional: also write user.lastLoginMethod
})

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: "http://localhost:8080"},
	Plugins:    []plugin.Plugin{lastLogin},
})
```

## Options

| Field | Default | Meaning |
|---|---|---|
| `CookieName` | `better-auth.last_used_login_method` | Cookie name (used as is: no cookie prefix, no `__Secure-`) |
| `MaxAge` | 30 days | Cookie lifetime |
| `CustomResolveMethod` | none | `func(c *endpointhooks.Context) (method string, ok bool)`; `ok=false` falls back to the default rules |
| `StoreInDatabase` | false | Also store the method in the user's `lastLoginMethod` field |
| `FieldName` | derived | Physical column of `lastLoginMethod` (better-auth's `schema.user.lastLoginMethod`) |

## Methods

The default rules are better-auth's:

| Endpoint | Method |
|---|---|
| `/sign-in/email`, `/sign-up/email` | `email` |
| `/callback/{id}` (social), `/oauth2/callback/{providerId}` (generic OAuth) | the provider id, e.g. `google` |
| `/magic-link/verify` | `magic-link` |
| `/passkey/verify-authentication` | `passkey` |
| paths containing `siwe` | `siwe` |

Other sign-ins (email OTP, phone number, username, one tap, anonymous) have no default method, as in
better-auth; add them with `CustomResolveMethod`:

```go
llmconfig.LastLoginMethodConfig{CustomResolveMethod: func(c *endpointhooks.Context) (string, bool) {
	if c.Path == "/sign-in/username" {
		return "username", true
	}
	return "", false
}}
```

## Flow

```sh
curl -i -X POST localhost:8080/api/auth/sign-in/email -H 'Content-Type: application/json' \
  -d '{"email":"a@example.com","password":"Password123!"}'
# Set-Cookie: better-auth.session_token=...; HttpOnly ...
# Set-Cookie: better-auth.last_used_login_method=email; Path=/; Max-Age=2592000; SameSite=Lax
```

In the browser:

```ts
const authClient = createAuthClient({ plugins: [lastLoginMethodClient()] });
authClient.getLastUsedLoginMethod();         // "email"
authClient.isLastUsedLoginMethod("google");  // false
authClient.clearLastUsedLoginMethod();
```

## Notes

- The cookie is only set when the response sets the session cookie, with the session cookie's attributes
  (path, domain, `Secure`, `SameSite`) but readable by JavaScript.
- `StoreInDatabase` declares the `lastLoginMethod` user field (string, not settable by clients) through
  `plugins.SchemaProvider`. Users created by a sign-in get it on insert; sessions created by a sign-in update
  their user. Failures are logged and never fail the sign-in. SetupGoAuth's migrator creates its column
  (`last_login_method`, or `lastLoginMethod` with `ColumnCase` camel) like any plugin schema field.
- When the two-factor plugin replaces a sign-in with its challenge, goauth sets no cookie and writes nothing:
  the challenge response carries no session cookie and its session is dropped. (better-auth expires the
  session cookie in that response, which makes its `includes(sessionTokenName)` check set the cookie, and its
  session hook has already written the field.) The two-factor verify endpoints have no default method.
