# Custom session plugin

Returns your own data from `GET /api/auth/get-session`. It is the Go version of better-auth's
`customSession(fn)` plugin and works with the better-auth `customSessionClient()` plugin.

Runnable example: [src/example/custom-session](../../example/custom-session/main.go)

```sh
go run ./src/example/custom-session    # server on http://localhost:8080
go test ./src/example/custom-session   # the flow below, end to end
```

## Setup

```go
import (
	customsession "github.com/better-go-auth/goauth/src/plugins/custom-session"
	csconfig "github.com/better-go-auth/goauth/src/plugins/custom-session/config"
)

sessionPlugin := customsession.New(func(ctx context.Context, s *csconfig.Session) (any, error) {
	roles, err := loadRoles(ctx, s.User.ID) // your own data
	if err != nil {
		return nil, err
	}
	return map[string]any{"roles": roles, "user": s.User, "session": s.Session}, nil
})

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: "http://localhost:8080"},
	Plugins:    []plugin.Plugin{sessionPlugin},
})
```

The callback receives a `*csconfig.Session`:

| Field | Meaning |
|---|---|
| `Session` | `dtos.SessionData` decoded from the core response |
| `User` | `dtos.UserResponse` decoded from the core response |
| `Raw` | The core response as JSON (`{"session": {...}, "user": {...}}`), including additional and plugin fields |
| `Request` | The incoming request |

Whatever the callback returns is sent as the JSON body. An error fails the request with that error (an
`*autherr.AuthError` keeps its status and code, anything else is a 500).

## Options

| Option | Default | Meaning |
|---|---|---|
| `customsession.WithMutateListDeviceSessions(true)` | false | Also maps every entry of the multi-session plugin's `GET /multi-session/list-device-sessions` (better-auth's `shouldMutateListDeviceSessionsEndpoint`) |

## Flow

```sh
curl -b cookies.txt localhost:8080/api/auth/get-session
# {"roles":["staff"],"session":{...},"user":{...}}
curl localhost:8080/api/auth/get-session        # no session
# null
```

With the official client:

```ts
const authClient = createAuthClient({ plugins: [customSessionClient<typeof auth>()] });
const { data } = await authClient.getSession(); // data.roles
```

## Notes

- better-auth replaces the core `getSession` endpoint; goauth keeps the core endpoint and rewrites its JSON body
  in an after hook. Cookie cache, session refresh, bearer tokens, the `disableCookieCache` / `disableRefresh`
  query and the response cookies and headers behave exactly like the core endpoint.
- Only successful responses with a session go through the callback; `null` stays `null`.
- better-auth's custom endpoint is GET only. goauth leaves `POST /get-session` (the `deferSessionRefresh`
  refresh) as the core endpoint, without the callback.
