# Open-api plugin

Publishes the OpenAPI 3.1 document of the auth routes in better-auth's format and an interactive
reference page (Scalar). It is the Go version of better-auth's `openAPI()` plugin: the same endpoints,
the same document shape and the same page.

Runnable example: [src/example/open-api](../../example/open-api/main.go)

```sh
go run ./src/example/open-api    # open http://localhost:8080/api/auth/reference
go test ./src/example/open-api
```

## Setup

```go
import (
	openapi "github.com/better-go-auth/goauth/src/plugins/open-api"
	openapiconfig "github.com/better-go-auth/goauth/src/plugins/open-api/config"
)

openAPIPlugin := openapi.New(openapiconfig.OpenAPIConfig{Theme: "purple"})

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: "http://localhost:8080"},
	Plugins:    []plugin.Plugin{openAPIPlugin, usernamePlugin},
})
```

The plugin order does not matter: the document is built on every request, from the routes registered
at that time.

## Options

| Field | Default | Meaning |
|---|---|---|
| `Path` | `/reference` | Path of the reference page, under BasePath (`/api/auth/reference`) |
| `DisableDefaultReference` | false | The page answers `404 NOT_FOUND`; the document stays available |
| `Theme` | `default` | Scalar theme (`alternate`, `moon`, `purple`, `solarized`, `bluePlanet`, `saturn`, `kepler`, `mars`, `deepSpace`, `laserwave`, `none`) |
| `Nonce` | none | `nonce` attribute of the page's scripts, for a Content-Security-Policy |
| `Schemas` | none | Extra plugin models for `components.schemas` |

Functional options: `openapi.WithPath`, `WithDisableDefaultReference`, `WithTheme`, `WithNonce`, and
`WithSchemaPlugins(plugins...)`. By default `components.schemas` comes from SetupGoAuth's schema registry,
which already contains every installed plugin implementing `plugins.SchemaProvider`; `WithSchemaPlugins`
instead lists the configuration's models plus exactly the given plugins.

## Endpoints (under `/api/auth`)

| Method | Path | Answer |
|---|---|---|
| GET | `/open-api/generate-schema` | The OpenAPI document (JSON) |
| GET | `/reference` (`Path`) | Scalar page (`text/html`) embedding the document; not listed in the document |

## The document

Same envelope as better-auth: `openapi: "3.1.1"`, `info` ("Better Auth"), `servers: [{url: "<BaseURL>/api/auth"}]`,
the `apiKeyCookie` and `bearerAuth` security schemes and the `Default` tag.

- `components.schemas`: `User`, `Session`, `Account`, `Verification` with better-auth's rules (dates are
  `string` / `date-time`, computed defaults are `"Generated at runtime"`, fields clients cannot set are
  `readOnly`, `required` lists required fields clients can set). The user/session fields of installed
  plugins are included (e.g. `username`), configuration `AdditionalFields` too; goauth-only columns are not.
- `paths`: every goauth route under BasePath, relative to it (`/sign-in/email`). Core routes are tagged
  `Default`, plugin routes with their capitalized tag (`One-time-token`, `Username`). Each operation has
  `security: [{bearerAuth: []}]`, better-auth's default 400/401/403/404/429/500 responses plus its own,
  query/path parameters and its JSON request body. Hidden routes, `DisabledPaths`, application routes
  outside BasePath and the plugin's own routes are left out. Everything is inlined (no `$ref`).

The request/response schemas come from Huma's own OpenAPI document (goauth's Go types), so they describe
what goauth actually accepts.

## Flow

```sh
curl http://localhost:8080/api/auth/open-api/generate-schema | jq '.paths | keys'
# ["/change-email", "/change-password", ..., "/sign-in/username", ...]
open http://localhost:8080/api/auth/reference
```

## Notes

- The embedded JSON escapes `<`, `>` and `&` as `<`..., so a description cannot close the script
  element; better-auth embeds it unescaped. The rest of the page is byte for byte better-auth's.
- Huma keeps serving its own full document at `/openapi.json` and `/docs`; this plugin is the auth-only,
  better-auth-shaped view.
