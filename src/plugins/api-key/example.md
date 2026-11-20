# API key plugin

API keys for your users (or organizations): scripts, CI jobs and other services call your API with an
`x-api-key` header instead of a session cookie. It is the Go version of `@better-auth/api-key` **1.6.16**
(better-auth's `apiKey()` plugin) and works with the official `apiKeyClient()`.

Runnable example: [src/example/api-key](../../example/api-key/main.go)

```sh
go run ./src/example/api-key     # server on http://localhost:8080, OpenAPI docs at /docs
go test ./src/example/api-key    # the flow below, end to end
```

## Setup

```go
import (
	apikey "github.com/better-go-auth/goauth/src/plugins/api-key"
	apikeyconfig "github.com/better-go-auth/goauth/src/plugins/api-key/config"
)

keys := apikey.New(apikeyconfig.Configuration{
	DefaultPrefix:           "myapp_",
	EnableMetadata:          true,
	EnableSessionForAPIKeys: true, // a key in x-api-key also signs requests to goauth's routes in
})

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: "http://localhost:8080"},
	Plugins:    []plugin.Plugin{keys},
})
```

The plugin declares better-auth's `apikey` table (`id, configId, name, start, referenceId, prefix, key,
refillInterval, refillAmount, lastRefillAt, enabled, rateLimitEnabled, rateLimitTimeWindow, rateLimitMax,
requestCount, remaining, lastRequest, expiresAt, createdAt, updatedAt, permissions, metadata`) through
`plugins.SchemaProvider`; goauth's migrator creates it (snake or camel columns, `GoAuth.ColumnCase`), and
`goauth.GenerateSQL` / the CLI include it. A TypeScript better-auth server can share the table: keys are
stored as better-auth stores them (SHA-256, base64url without padding).

Several configurations (better-auth's `apiKey([...])`) are created with
`apikey.NewWithConfigurations([]apikeyconfig.Configuration{{ConfigID: "default"}, {ConfigID: "partner", ...}})`;
each key remembers its `configId`, requests choose one with `configId`.

## Options (`apikeyconfig.Configuration`)

| Field | Default | Meaning |
|---|---|---|
| `ConfigID` | `""` (= `default`) | Name of the configuration (required with several) |
| `APIKeyHeaders` | `["x-api-key"]` | Headers the key is read from, in order |
| `CustomAPIKeyGetter` | none | `func(*http.Request) string` instead of the headers |
| `CustomAPIKeyValidator` | none | Extra check of a presented key |
| `CustomKeyGenerator` | prefix + 64 random letters | `func(ctx, length, prefix) (string, error)` |
| `DefaultKeyLength` | 64 | Random characters per key; shorter keys in a header are rejected (403) |
| `DefaultPrefix` | none | Prepended to new keys and stored in `prefix` |
| `MinimumPrefixLength` / `MaximumPrefixLength` | 1 / 32 | Bounds of a custom `prefix` |
| `RequireName`, `MinimumNameLength` / `MaximumNameLength` | false, 1 / 32 | Name rules |
| `EnableMetadata` | false | Allow the `metadata` object |
| `DisableKeyHashing` | false | Store keys in plain text (not recommended) |
| `StartingCharactersConfig` | store 6 | `start` holds the first characters (prefix included) for display |
| `KeyExpiration` | no default, 1..365 days | `DefaultExpiresIn` (Duration), `DisableCustomExpiresTime`, `MinExpiresIn` / `MaxExpiresIn` (days) |
| `RateLimit` | on, 10 per day | `Enabled`, `TimeWindow`, `MaxRequests`: defaults of new keys |
| `Permissions` | none | `DefaultPermissions` (or `DefaultPermissionsFunc(ctx, referenceID)`) for new keys |
| `EnableSessionForAPIKeys` | false | A valid key on any goauth route acts as its owner's session (not stored) |
| `Storage` | `database` | `secondary-storage` keeps keys in `GoAuthOptions.SecondaryStorage` (or `CustomStorage`) |
| `FallbackToDatabase` | false | With `secondary-storage`: write both, read the store first, fill it from the database |
| `CustomStorage` | none | `Get` / `Set` / `Delete` store used instead of the secondary storage |
| `DeferUpdates` | false | Usage counters and cleanups run through `Advanced.BackgroundTasks.Handler` |
| `References` | `user` | `organization` makes keys belong to organizations (see below) |

Plugin options: `apikey.WithSchema(apikeyconfig.SchemaOptions{ModelName, Fields})` renames the table and
columns, `apikey.WithOrganization(apikey.OrganizationFrom(orgPlugin))` connects organization keys,
`apikey.WithClock(fn)` replaces the clock (tests).

## Endpoints (under `/api/auth`)

| Method | Path | Session | Body / query | Response |
|---|---|---|---|---|
| POST | `/api-key/create` | required for clients | `name?`, `expiresIn?` (s), `prefix?`, `metadata?`, `configId?`, `organizationId?` | the key **with** `key` (only time it is shown) |
| GET | `/api-key/get` | required | `?id=&configId=` | the key without `key` |
| POST | `/api-key/update` | required for clients | `keyId`, `name?`, `enabled?`, `expiresIn?` (null removes), `metadata?` | the key |
| POST | `/api-key/delete` | required | `keyId`, `configId?` | `{"success": true}` |
| GET | `/api-key/list` | required | `?configId=&organizationId=&limit=&offset=&sortBy=&sortDirection=` | `{"apiKeys": [...], "total", "limit"?, "offset"?}` |

`remaining`, `refillAmount`, `refillInterval`, `rateLimitEnabled`, `rateLimitTimeWindow`,
`rateLimitMax`, `permissions` and `userId` are **server-only**: from a client they answer
`400 SERVER_ONLY_PROPERTY` (`userId`: `401 UNAUTHORIZED_SESSION`). better-auth's `verifyApiKey` and
`deleteAllExpiredApiKeys` have no route in 1.6.16; they are Go methods here.

## Server-side Go API

```go
// a key with 100 uses refilled every hour, 5 requests per second, and permissions
k, err := keys.CreateAPIKey(ctx, apikey.CreateAPIKeyInput{
	UserID: &userID, Name: ptr("ci"), Remaining: ptr[int64](100),
	RefillAmount: ptr[int64](100), RefillInterval: ptr[int64](3_600_000),
	RateLimitTimeWindow: ptr[int64](1000), RateLimitMax: ptr[int64](5),
	Permissions: map[string][]string{"reports": {"read"}},
})
res, err := keys.VerifyAPIKey(ctx, apikey.VerifyAPIKeyInput{Key: k.Key, Permissions: map[string][]string{"reports": {"read"}}})
// res.Valid, res.Error.Code (e.g. "RATE_LIMITED", res.Error.Details["tryAgainIn"]), res.Key
keys.UpdateAPIKey(ctx, apikey.UpdateAPIKeyInput{KeyID: k.ID, UserID: &userID, Permissions: apikey.Null[map[string][]string]()})
keys.GetAPIKey(ctx, k.ID, "", userID)
keys.ListAPIKeys(ctx, userID, apikey.ListAPIKeysInput{SortBy: "createdAt", SortDirection: "desc"})
keys.DeleteAPIKey(ctx, k.ID, "", userID)
keys.DeleteAllExpiredAPIKeys(ctx)
```

## Protecting your own routes with keys

`keys.Middleware` (Huma) and `keys.HTTPMiddleware` (net/http) authenticate a route by API key, with or
without `EnableSessionForAPIKeys`. Each use is recorded (remaining, rate limit). The context then carries
the key (`apikey.FromContext`) and, for user keys, the owner's session (`apikey.SessionFromContext`,
goauth's session middlewares and `authenticator.SessionFromContext`):

```go
huma.Register(api, huma.Operation{
	Method: http.MethodGet, Path: "/api/reports",
	Middlewares: huma.Middlewares{keys.Middleware(apikey.MiddlewareOptions{
		Permissions: map[string][]string{"reports": {"read"}}, // 401 KEY_NOT_FOUND without it
	})},
}, func(ctx context.Context, _ *struct{}) (*Out, error) {
	k, _ := apikey.FromContext(ctx)
	sw, _ := apikey.SessionFromContext(ctx)
	...
})
```

`Optional: true` lets requests without a key through; `ConfigID` accepts only one configuration's keys.

## Flow

```sh
# 1. sign up (session cookie in jar), then create a key
curl -c jar -H 'Origin: http://localhost:8080' -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"Password123!","name":"Alice"}' \
  http://localhost:8080/api/auth/sign-up/email
curl -b jar -H 'Origin: http://localhost:8080' -H 'Content-Type: application/json' \
  -d '{"name":"ci","metadata":{"team":"ops"}}' http://localhost:8080/api/auth/api-key/create
# → {"id":"...","key":"ex_AbC...","start":"ex_AbC","permissions":{"reports":["read"]},...}

# 2. a script calls your route, and goauth's routes, with the key
curl -H 'x-api-key: ex_AbC...' http://localhost:8080/api/example/reports
curl -H 'x-api-key: ex_AbC...' http://localhost:8080/api/auth/get-session

# 3. manage keys with the session
curl -b jar 'http://localhost:8080/api/auth/api-key/list?sortBy=createdAt&sortDirection=desc'
curl -b jar -H 'Origin: http://localhost:8080' -H 'Content-Type: application/json' \
  -d '{"keyId":"..."}' http://localhost:8080/api/auth/api-key/delete
```

## Usage limits, rate limits, expiry

- `remaining` counts down on every verification; at 0 without `refillAmount` the key is deleted and
  `429 USAGE_EXCEEDED` is answered. With `refillAmount` + `refillInterval` (ms) it is reset to
  `refillAmount` once `refillInterval` has passed since the last refill (or creation).
- Rate limit: `rateLimitMax` requests per `rateLimitTimeWindow` (ms) per key; then
  `429 {"code":"RATE_LIMITED","message":"Rate limit exceeded.","details":{"tryAgainIn":<ms>}}`.
- An expired key is deleted when presented (`401 KEY_EXPIRED`); expired keys are also removed (at most every
  10 seconds) whenever keys are created, read, updated, listed or used as a session.

## Organization keys

With `References: apikeyconfig.ReferencesOrganization`, keys belong to an organization (`organizationId`
on create and list). Members need the organization role permission `apiKey: [create|read|update|delete]`
(the creator role, default `owner`, has all of them); add the `apiKey` resource to your organization access
control. Connect the plugins with `apikey.WithOrganization(apikey.OrganizationFrom(orgPlugin))`.
Organization keys never become sessions (`401 INVALID_REFERENCE_ID_FROM_API_KEY`).

## Errors

| Code | Status | When |
|---|---|---|
| `UNAUTHORIZED_SESSION` | 401 | create / update without a session, or `userId` from a client |
| `SERVER_ONLY_PROPERTY` | 400 | a server-only property from a client |
| `KEY_NOT_FOUND` | 404 / 401 | unknown key or not yours (404); permission check failed or custom validator said no (401) |
| `INVALID_API_KEY` | 401 / 403 | unknown key (401); key shorter than `DefaultKeyLength` or rejected by the validator in a header (403) |
| `KEY_DISABLED` / `KEY_EXPIRED` | 401 | disabled / expired key |
| `USAGE_EXCEEDED` | 429 | `remaining` is 0 |
| `RATE_LIMITED` | 429 | the key's rate limit (with `details.tryAgainIn`) |
| `EXPIRES_IN_IS_TOO_SMALL` / `_LARGE`, `KEY_DISABLED_EXPIRATION` | 400 | expiry rules |
| `INVALID_PREFIX_LENGTH`, `INVALID_NAME_LENGTH`, `NAME_REQUIRED` | 400 | prefix / name rules |
| `METADATA_DISABLED`, `INVALID_METADATA_TYPE` | 400 | metadata rules |
| `REFILL_AMOUNT_AND_INTERVAL_REQUIRED` / `REFILL_INTERVAL_AND_AMOUNT_REQUIRED` | 400 | only one refill value |
| `NO_VALUES_TO_UPDATE` | 400 | update without changes |
| `USER_BANNED` | 401 | banned user deletes a key |
| `ORGANIZATION_ID_REQUIRED`, `USER_NOT_MEMBER_OF_ORGANIZATION`, `INSUFFICIENT_API_KEY_PERMISSIONS`, `ORGANIZATION_PLUGIN_REQUIRED` | 400 / 403 / 403 / 500 | organization keys |
| `NO_DEFAULT_API_KEY_CONFIGURATION_FOUND` | 400 | no `configId` and no default configuration |
| `INVALID_REFERENCE_ID_FROM_API_KEY` | 401 | session from a key whose owner is gone or is an organization |
| `FAILED_TO_UPDATE_API_KEY` | 500 | the key vanished while its use was recorded |

## Notes

- The mocked session of a key has `id` = key id, `token` = the key, and expires with the key or after the
  session lifetime **in milliseconds** (better-auth 1.6.16 adds `session.expiresIn` seconds as ms; kept
  for parity).
- `INVALID_API_KEY_GETTER_RETURN_TYPE` cannot happen in Go (the getter returns a string).
- Numbers (`remaining`, intervals, windows) are whole numbers in Go; JSON numbers with a fraction are
  rounded.
