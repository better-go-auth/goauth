# SCIM plugin

SCIM 2.0 user provisioning (RFC 7643 / RFC 7644) for identity providers such as Okta or Entra ID. It is the
Go version of `@better-auth/scim` 1.6.16 and works with the official `scimClient()` from
`@better-auth/scim/client`.

Runnable example: [src/example/scim](../../example/scim/main.go)

```sh
go run ./src/example/scim     # server on http://localhost:8080, OpenAPI docs at /docs
go test ./src/example/scim    # generates a token, provisions, updates and deprovisions a user
```

## Setup

```go
import (
	"github.com/better-go-auth/goauth/src/plugins/scim"
	scimconfig "github.com/better-go-auth/goauth/src/plugins/scim/config"
)

scimPlugin := scim.New(scimconfig.SCIMConfig{
	ProviderOwnership: true,                                           // connections belong to their creator
	StoreSCIMToken:    scimconfig.TokenStorage{Mode: scimconfig.StoreHashed}, // plain (default), hashed, encrypted
})
// add the organization plugin to scope tokens to organizations
```

The plugin declares the `scimProvider` table (`id, providerId, scimToken, organizationId` and `userId` with
`ProviderOwnership`); goauth's migrator creates it.

## Options (`scimconfig.SCIMConfig`)

| Field | Default | Meaning |
|---|---|---|
| `ProviderOwnership` | false | Store the creating user on the connection; only they manage personal connections |
| `RequiredRole` | `admin` + creator role (`owner`) | Organization roles that may manage organization connections |
| `DefaultSCIM` | – | Connections configured in code (`ProviderID`, `SCIMToken` = the plain secret, `OrganizationID`) |
| `LinkExistingUsers` | off (409) | `All`, `TrustedDomains`, `RequireExistingOrgMembership`, `ShouldLinkUser`: when provisioning may attach to an existing user with the same email |
| `BeforeSCIMTokenGenerated` / `AfterSCIMTokenGenerated` | – | Hooks around token creation |
| `CanGenerateToken` | – | Extra authorization of token creation |
| `StoreSCIMToken` | plain | `Mode` `hashed` (SHA-256) / `encrypted` (auth secret), or `Hash` / `Encrypt` + `Decrypt` |

## Endpoints (under `/api/auth`)

Management (session):

| Method | Path | Notes |
|---|---|---|
| POST | `/scim/generate-token` | `providerId`, `organizationId?` → 201 `{scimToken}`; a new token replaces the old one |
| GET | `/scim/list-provider-connections` | `{providers: [{id, providerId, organizationId}]}` |
| GET | `/scim/get-provider-connection?providerId=` | |
| POST | `/scim/delete-provider-connection` | `{success: true}`; the token stops working |

SCIM 2.0 (`Authorization: Bearer <scimToken>`, `application/scim+json` or `application/json`):

| Method | Path | Notes |
|---|---|---|
| POST | `/scim/v2/Users` | `userName` (lowercase), `externalId?`, `name?`, `emails?` → 201 + `Location`; joins the token's organization as `member` |
| GET | `/scim/v2/Users?filter=userName eq "x"` | ListResponse of the provider's users (one page, at most 100, like better-auth) |
| GET | `/scim/v2/Users/{id}` | |
| PUT | `/scim/v2/Users/{id}` | Replaces email, name and externalId |
| PATCH | `/scim/v2/Users/{id}` | PatchOp; `add` / `replace` on `name.formatted`, `name.givenName`, `name.familyName`, `userName`, `externalId` → 204 |
| DELETE | `/scim/v2/Users/{id}` | Organization token: removes the membership and the SCIM account; personal token: deletes the user → 204 |
| GET | `/scim/v2/ServiceProviderConfig`, `/scim/v2/Schemas[/{id}]`, `/scim/v2/ResourceTypes[/{id}]` | Public metadata |

Like better-auth, PATCH ignores `remove` operations and unmapped paths such as `active`: an `active: false`
PATCH alone is answered with 400 `No valid fields to update`; identity providers deprovision with DELETE.

## Flow

```sh
# 1. an organization admin creates the token for the IdP connection
curl -b jar -H 'Origin: http://localhost:8080' -H 'Content-Type: application/json' \
  -d '{"providerId":"okta","organizationId":"<orgId>"}' http://localhost:8080/api/auth/scim/generate-token

# 2. the IdP provisions users with it
curl -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/scim+json' \
  -d '{"userName":"jane@acme.com","name":{"givenName":"Jane","familyName":"Doe"}}' \
  http://localhost:8080/api/auth/scim/v2/Users
```

## Errors

SCIM endpoints answer RFC 7644 errors:
`{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"409","detail":"User already exists","scimType":"uniqueness"}`
(401 `SCIM token is required` / `Invalid SCIM token`, 404 `User not found`, 409 uniqueness, 400
`invalidFilter`, 400 `No valid fields to update`). Body validation errors are better-auth's
`VALIDATION_ERROR` (`[body.userName] Invalid lowercase`, ...). The management endpoints use better-auth's
messages (`Provider id contains forbidden characters`, `Insufficient role for this operation`, ...).
