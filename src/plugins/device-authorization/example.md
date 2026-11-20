# Device authorization plugin

Lets devices without a browser or keyboard (CLIs, TVs, IoT) sign a user in with the OAuth 2.0 Device
Authorization Grant ([RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)). It is the Go version of
better-auth's `deviceAuthorization()` plugin and works with the better-auth `deviceAuthorizationClient()`
plugin.

Runnable example: [src/example/device-authorization](../../example/device-authorization/main.go)

```sh
go run ./src/example/device-authorization     # server on http://localhost:8080, OpenAPI docs at /docs
go test ./src/example/device-authorization    # the flow below, end to end
```

## Setup

```go
import (
	deviceauthorization "github.com/better-go-auth/goauth/src/plugins/device-authorization"
	daconfig "github.com/better-go-auth/goauth/src/plugins/device-authorization/config"
	"github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
)

devicePlugin := deviceauthorization.New(daconfig.DeviceAuthorizationConfig{
	ExpiresIn: 30 * time.Minute, // default
	Interval:  5 * time.Second,  // default
	ValidateClient: func(ctx context.Context, clientID string) (bool, error) {
		return clientID == "my-cli", nil
	},
	VerificationURI: "/device", // your page where users enter the code
})

unsigned := false
auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: "http://localhost:8080"},
	Plugins: []plugin.Plugin{
		devicePlugin,
		// lets the device send the issued token as "Authorization: Bearer <token>"
		bearer.New(bearerconfig.BearerConfig{RequireSignature: &unsigned}),
	},
})
```

The plugin declares better-auth's `deviceCode` table (`deviceCode`, `userCode`, `userId`, `expiresAt`,
`status`, `lastPolledAt`, `pollingInterval`, `clientId`, `scope`). goauth's migrator creates it during
`SetupGoAuth` (snake_case or camelCase columns, like the rest of the schema).

## Options

| Field | Default | Meaning |
|---|---|---|
| `ExpiresIn` | 30 min | Lifetime of a device code / user code pair |
| `Interval` | 5 s | Minimum time between two polls; faster polls get `slow_down` |
| `DeviceCodeLength` | 40 | Length of generated device codes (`[a-zA-Z0-9]`) |
| `UserCodeLength` | 8 | Length of generated user codes (`ABCDEFGHJKLMNPQRSTUVWXYZ23456789`) |
| `GenerateDeviceCode` / `GenerateUserCode` | random | Custom generators |
| `ValidateClient` | accept all | Checks `client_id` on `/device/code` and `/device/token` |
| `OnDeviceAuthRequest` | none | Called for every accepted `/device/code` request (an error aborts it) |
| `VerificationURI` | `/device` | Absolute URL or path (resolved against the base URL) returned as `verification_uri` |
| `ModelName` / `FieldNames` | `deviceCode` | Rename the table or its columns |

`deviceauthorization.WithValidateClient`, `WithOnDeviceAuthRequest` and `WithVerificationURI` are the
functional-option forms.

## Endpoints (under `/api/auth`)

| Method | Path | Body / query | Notes |
|---|---|---|---|
| POST | `/device/code` | `client_id`, `scope?` | RFC 8628 §3.2 response. JSON or form body |
| POST | `/device/token` | `grant_type=urn:ietf:params:oauth:grant-type:device_code`, `device_code`, `client_id` | JSON or form body |
| GET | `/device` | `?user_code=` | `{user_code, status}`. A signed-in caller claims the code |
| POST | `/device/approve` | `userCode` | Session required; only the user who claimed the code |
| POST | `/device/deny` | `userCode` | Session required; only the user who claimed the code |

User codes are matched with dashes removed, so `ABCD-EFGH` works too.

## The flow

```sh
# 1. the device asks for a code
curl -X POST localhost:8080/api/auth/device/code -d 'client_id=my-cli&scope=openid'
# {"device_code":"…40 chars…","user_code":"WDJB7KQX","verification_uri":"http://localhost:8080/device",
#  "verification_uri_complete":"http://localhost:8080/device?user_code=WDJB7KQX","expires_in":1800,"interval":5}

# 2. the device polls every `interval` seconds
curl -X POST localhost:8080/api/auth/device/token \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=…&client_id=my-cli'
# 400 {"error":"authorization_pending","error_description":"Authorization pending"}

# 3. in the browser, signed in: claim, then approve
curl 'localhost:8080/api/auth/device?user_code=WDJB7KQX' -b cookies.txt
curl -X POST localhost:8080/api/auth/device/approve -b cookies.txt -H 'Origin: http://localhost:8080' \
  -H 'Content-Type: application/json' -d '{"userCode":"WDJB7KQX"}'

# 4. the next poll returns the session token
# {"access_token":"…","token_type":"Bearer","expires_in":604800,"scope":"openid"}
curl localhost:8080/api/auth/get-session -H 'Authorization: Bearer …'
```

With the official client:

```ts
const client = createAuthClient({ plugins: [deviceAuthorizationClient()] });
const { data } = await client.device.code({ client_id: "my-cli" });
// … show data.user_code / data.verification_uri, then poll:
const token = await client.device.token({
  grant_type: "urn:ietf:params:oauth:grant-type:device_code",
  device_code: data.device_code,
  client_id: "my-cli",
});
// in the browser: await client.device({ query: { user_code } }); await client.device.approve({ userCode: user_code });
```

## Errors

The device endpoints answer RFC 6749 style errors, exactly like better-auth:

| Situation | Status | `error` | `error_description` |
|---|---|---|---|
| Unknown client on `/device/code` | 400 | `invalid_client` | Invalid client ID |
| Unknown client / unknown device code / other client's code | 400 | `invalid_grant` | Invalid client ID / Invalid device code / Client ID mismatch |
| Not decided yet | 400 | `authorization_pending` | Authorization pending |
| Polling faster than `interval` | 400 | `slow_down` | Polling too frequently |
| Code expired | 400 | `expired_token` | Device code has expired / User code has expired |
| User denied | 400 | `access_denied` | Access denied |
| Unknown user code | 400 | `invalid_request` | Invalid user code |
| Approve/deny twice | 400 | `invalid_request` | Device code already processed |
| Approve/deny before `GET /device` | 400 | `invalid_request` | Device code has not been claimed … |
| Approve/deny without session | 401 | `unauthorized` | Authentication required |
| Approve/deny a code claimed by someone else | 403 | `access_denied` | You are not authorized to … |

Missing or invalid body fields are better-auth's `400 VALIDATION_ERROR` (`{code, message}`).

## Notes

- The token is the new session's token (`expires_in` = the session lifetime); the response sets no cookie.
- Device codes are single use: denied, expired and redeemed codes are deleted; concurrent polls of an
  approved code yield exactly one session.
- `Service().FindByUserCode` lets your verification page show the requesting client and scope.
