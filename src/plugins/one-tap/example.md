# One-tap plugin

Signs users in with Google One Tap / "Sign in with Google". The browser shows Google's prompt, Google
hands the page an ID token (the `credential`), and the page posts it to `POST /api/auth/one-tap/callback`.
goauth checks the token against Google's keys, then signs the user in, links the Google account to an
existing user with the same email, or creates a new user. It is the Go version of better-auth's
`oneTap()` plugin and works with the better-auth `oneTapClient()` plugin.

Runnable example: [src/example/one-tap](../../example/one-tap/main.go)

```sh
GOOGLE_CLIENT_ID=... go run ./src/example/one-tap   # page with the One Tap prompt on http://localhost:8080
go test ./src/example/one-tap                        # the flow below, against a fake Google key set
```

## Setup

```go
import (
	onetap "github.com/better-go-auth/goauth/src/plugins/one-tap"
	onetapconfig "github.com/better-go-auth/goauth/src/plugins/one-tap/config"
)

oneTapPlugin := onetap.New(onetapconfig.OneTapConfig{
	ClientID: os.Getenv("GOOGLE_CLIENT_ID"),
})

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: "http://localhost:8080"},
	Plugins:    []plugin.Plugin{oneTapPlugin},
})
```

With the social plugin installed, pass it so One Tap uses its Google client ID and its account options
(account linking policy, encrypted tokens):

```go
socialPlugin := social.New(socialconfig.SocialConfig{Providers: []providers.Provider{google}})
oneTapPlugin := onetap.New(onetapconfig.OneTapConfig{}, onetap.WithSocialPlugin(socialPlugin))
```

Accounts are stored with `providerId: "google"`, so One Tap and the social plugin's Google sign-in share
one account. The plugin has no tables of its own.

## Options

| Field | Default | Meaning |
|---|---|---|
| `ClientID` | social plugin's `google` client ID | The Google client ID the token must be issued for (`aud`). With no client ID at all, the audience is not checked (like better-auth) |
| `DisableSignup` | false | Unknown Google accounts get `401 "signup disabled"`. Existing users still sign in |
| `JWKSURL` | `https://www.googleapis.com/oauth2/v3/certs` | Google's key set (tests use a fake one) |
| `HTTPClient` | 10 s timeout | Client used to fetch the key set |

Functional options: `onetap.WithClientID`, `WithDisableSignup`, `WithJWKSURL`, `WithHTTPClient`,
`WithSocialPlugin`.

## Endpoint (under `/api/auth`)

| Method | Path | Body | Answer |
|---|---|---|---|
| POST | `/one-tap/callback` | `{ "idToken": "<Google credential>" }` | `200 { token, user }` and the session cookie |

The token must be signed by Google (JWKS), issued by `https://accounts.google.com` or
`accounts.google.com`, and not expired. The email is lower-cased; `email_verified` may be a boolean or the
string `"true"`.

## Flow

```js
// browser, with Google Identity Services loaded
google.accounts.id.initialize({
  client_id: GOOGLE_CLIENT_ID,
  callback: (res) => fetch("/api/auth/one-tap/callback", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ idToken: res.credential }),
  }),
});
google.accounts.id.prompt();
```

With the better-auth client: `createAuthClient({ plugins: [oneTapClient({ clientId })] })` and
`authClient.oneTap()` (browser only; outside a browser it returns `undefined`).

```sh
curl -c jar -H 'Origin: http://localhost:8080' -H 'Content-Type: application/json' \
  -d '{"idToken":"eyJhbGciOiJSUzI1NiIs..."}' http://localhost:8080/api/auth/one-tap/callback
# {"token":"...","user":{"id":"...","email":"ada@example.com","emailVerified":true,...}}
curl -b jar http://localhost:8080/api/example/me
```

## Errors

| Status | Body | When |
|---|---|---|
| 400 | `{ code: "BAD_REQUEST", message: "invalid id token" }` | Bad signature, wrong issuer or audience, expired, not a JWT |
| 200 | `{ error: "Email not available in token" }` | The token has no email (no session is created) |
| 401 | `{ code: "UNAUTHORIZED", message: "signup disabled" }` | `DisableSignup` and an unknown account |
| 401 | `{ code: "UNAUTHORIZED", message: "account not linked" }` | An existing user with the same email, and the linking policy refuses (unverified Google email, unverified local email, linking disabled) |
| 400 | `VALIDATION_ERROR` | `idToken` missing |

better-auth sends the 400 and 401 errors without a `code`; goauth uses the status name as code, like for
every message-only error.

## Notes

- The route is a normal mutating route: requests with cookies need a trusted `Origin`.
- `AuthConfig.DisabledOps: []consts.OperationId{"oneTapCallback"}` (or `DisabledPaths`) turns the route off.
