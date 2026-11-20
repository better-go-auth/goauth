# SSO plugin

Enterprise single sign-on with OIDC and SAML 2.0 identity providers (Okta, Entra ID, Google Workspace,
Keycloak, ...), registered per user or per organization. It is the Go version of `@better-auth/sso` 1.6.16
and works with the official `ssoClient()` from `@better-auth/sso/client`.

Runnable example: [src/example/sso](../../example/sso/main.go)

```sh
go run ./src/example/sso      # server on http://localhost:8080, OpenAPI docs at /docs
go test ./src/example/sso     # registers an OIDC provider and signs an employee in through a fake IdP
```

## Setup

```go
import (
	"github.com/better-go-auth/goauth/src/plugins/org"
	"github.com/better-go-auth/goauth/src/plugins/sso"
	ssoconfig "github.com/better-go-auth/goauth/src/plugins/sso/config"
)

orgPlugin, _ := org.NewWithGorm(db, orgconfig.OrgConfig{}) // optional: organization providers
ssoPlugin := sso.New(ssoconfig.SSOConfig{
	OrganizationProvisioning: &ssoconfig.OrganizationProvisioning{DefaultRole: "member"},
})

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: "https://app.example.com"},
	Plugins:    []plugin.Plugin{orgPlugin, ssoPlugin},
})
```

The plugin declares the `ssoProvider` table (`id, issuer, oidcConfig, samlConfig, userId, providerId,
organizationId, domain` and `domainVerified` with domain verification). goauth's migrator creates it; the
names follow `GoAuth.ColumnCase` (`sso_provider` / `ssoProvider`), `ModelName` and `Fields` rename them.

OIDC endpoints of a provider are fetched by the server, so they must be publicly routable, or their origin
must be in `TrustedOrigins` (internal IdPs). The discovery URL itself must always be a trusted origin.

## Options (`ssoconfig.SSOConfig`)

| Field | Default | Meaning |
|---|---|---|
| `ProvisionUser` / `ProvisionUserOnEveryLogin` | – / false | Callback after an SSO sign-in that created the user (or every sign-in) |
| `OrganizationProvisioning` | add as `member` | `Disabled`, `DefaultRole` or `GetRole` for users of organization providers |
| `DefaultSSO` | – | Providers configured in code (`Domain`, `ProviderID`, `OIDCConfig` / `SAMLConfig`); they win over the database |
| `DefaultOverrideUserInfo` | false | `overrideUserInfo` of providers registered without it |
| `DisableImplicitSignUp` | false | New users need `requestSignUp: true` at sign-in |
| `ProvidersLimit` (+`ProvidersLimitSet`) / `ProvidersLimitFunc` | 10 | Providers a user may register; 0 disables registration |
| `TrustEmailVerified` | false | Trust the IdP `email_verified` claim (deprecated upstream) |
| `DomainVerification` | off | `Enabled`, `TokenPrefix` (`better-auth-token`), `LookupTXT` (DNS resolver, for tests) |
| `RedirectURI` | per provider | One shared OIDC redirect URI (`/sso/callback`) for every provider |
| `SAML` | | `EnableInResponseToValidation` (true), `AllowIdpInitiated` (true), `RequestTTL` (5m), `ClockSkew` (5m), `RequireTimestamps`, `Algorithms`, `MaxResponseSize` (256 KB), `MaxMetadataSize` (100 KB), `EnableSingleLogout`, `LogoutRequestTTL` |
| `ModelName` / `Fields` | `ssoProvider` | Table and column names |
| `HTTPClient` / `LookupHost` | 10s, no redirects / DNS | goauth extras for the server-side OIDC requests |

Account linking, token encryption and the OAuth state strategy come from the core `AuthConfig.Account`
options, like better-auth.

## Endpoints (under `/api/auth`)

| Method | Path | Notes |
|---|---|---|
| POST | `/sso/register` | Session. `providerId`, `issuer`, `domain` (comma-separated list allowed), `oidcConfig` or `samlConfig`, `organizationId?`, `overrideUserInfo?`. OIDC runs discovery unless `skipDiscovery` |
| POST | `/sign-in/sso` | `email`, `domain`, `providerId` or `organizationSlug`, `callbackURL`, `errorCallbackURL?`, `newUserCallbackURL?`, `scopes?`, `loginHint?`, `requestSignUp?`, `providerType?` → `{url, redirect: true}` |
| GET | `/sso/callback/{providerId}` | OIDC redirect URI (and `/sso/callback` with `RedirectURI`) |
| GET, POST | `/sso/saml2/callback/{providerId}` | SAML POST binding (and the GET redirect of signed-in browsers) |
| POST | `/sso/saml2/sp/acs/{providerId}` | Assertion Consumer Service; 400 errors redirect with `error` / `error_description` |
| GET | `/sso/saml2/sp/metadata?providerId=` | SP metadata XML |
| GET, POST | `/sso/saml2/sp/slo/{providerId}` | Single Logout (with `SAML.EnableSingleLogout`) |
| POST | `/sso/saml2/logout/{providerId}` | Session. Starts SP-initiated Single Logout |
| GET | `/sso/providers` | Session. The user's providers and those of organizations they administer (sanitized) |
| GET | `/sso/get-provider?providerId=` | Session |
| POST | `/sso/update-provider` | Session. Partial update; a new domain resets `domainVerified` |
| POST | `/sso/delete-provider` | Session |
| POST | `/sso/request-domain-verification` | Session, domain verification only. 201 `{domainVerificationToken}` |
| POST | `/sso/verify-domain` | Session, domain verification only. Checks the TXT record `_<prefix>-<providerId>.<domain>` = `_<prefix>-<providerId>=<token>`; 204 |

## Flow (OIDC)

```sh
# 1. an admin registers the company IdP (discovery fills the endpoints)
curl -b jar -H 'Origin: http://localhost:8080' -H 'Content-Type: application/json' \
  -d '{"providerId":"acme","issuer":"https://idp.acme.com","domain":"acme.com",
       "oidcConfig":{"clientId":"...","clientSecret":"..."}}' \
  http://localhost:8080/api/auth/sso/register

# 2. an employee starts the sign-in with their work email; open the returned url in the browser
curl -c jar2 -H 'Origin: http://localhost:8080' -H 'Content-Type: application/json' \
  -d '{"email":"jane@acme.com","callbackURL":"/dashboard"}' \
  http://localhost:8080/api/auth/sign-in/sso
# 3. the IdP redirects to /api/auth/sso/callback/acme, which sets the session cookie and redirects to /dashboard
```

With the official client:

```ts
import { createAuthClient } from "better-auth/client";
import { ssoClient } from "@better-auth/sso/client";
const client = createAuthClient({ baseURL: "http://localhost:8080", plugins: [ssoClient()] });
await client.sso.register({ providerId: "acme", issuer, domain: "acme.com", oidcConfig: { clientId, clientSecret } });
await client.signIn.sso({ email: "jane@acme.com", callbackURL: "/dashboard" });
```

## SAML

Register with `samlConfig`: `entryPoint` (IdP SSO URL) and `cert` (IdP signing certificate), or
`idpMetadata.metadata` (IdP metadata XML); `callbackUrl` (the ACS URL given to the IdP, e.g.
`https://app.example.com/api/auth/sso/saml2/callback/<providerId>`), `spMetadata.entityID` (the SP entity ID /
audience), optional `mapping` (attribute names: `id`, `email`, `name`, `firstName`, `lastName`,
`extraFields`), `authnRequestsSigned` + `privateKey`, `identifierFormat`, `signatureAlgorithm`.

SAML messages are validated with [`github.com/crewjam/saml`](https://github.com/crewjam/saml): XML signature
(response or assertion) against the IdP certificate, issuer, audience (SP entity ID or `audience`),
destination / recipient, status, subject confirmation and timestamps. On top, like better-auth, the plugin
checks exactly one assertion, the algorithms (`SAML.Algorithms`), `NotBefore` / `NotOnOrAfter` with
`SAML.ClockSkew`, `InResponseTo` against the stored AuthnRequest IDs (one use each) and assertion replay
(an assertion ID is accepted once until it expires).

## Errors

API errors use better-auth's messages and statuses (`{message}` or `{code, message}`), for example 422
`SSO provider with this providerId already exists`, 404 `No provider found for the issuer`, 401
`Provider domain has not been verified`, 400 `discovery_*` / `issuer_mismatch` codes for OIDC discovery,
`SAML_MULTIPLE_ASSERTIONS`, `SAML_NO_ASSERTION`, `SAML_INVALID_ENCODING`, `SAML_UNKNOWN_ALGORITHM`,
`SAML_ALGORITHM_NOT_ALLOWED`, the domain verification codes (`PROVIDER_NOT_FOUND`, `INSUFICCIENT_ACCESS`,
`DOMAIN_VERIFIED`, `NO_PENDING_VERIFICATION`, `DOMAIN_VERIFICATION_FAILED`) and the SLO codes
(`SINGLE_LOGOUT_NOT_ENABLED`, `INVALID_LOGOUT_REQUEST`, ...). Callback failures redirect to the error URL
with `?error=...&error_description=...` (`invalid_provider`, `state_mismatch`, `account not linked`,
`signup disabled`, `invalid_saml_response`, `replay_detected`, `unsolicited_response`, ...).

## Differences from better-auth

- The SAML library is crewjam/saml instead of samlify. It always requires a signed response or assertion,
  enforces its own tolerances (3 minutes clock skew, responses issued at most 90 seconds earlier) in addition
  to `SAML.ClockSkew`, and requires IdP Single Logout messages to be signed (`WantLogoutRequestSigned` /
  `WantLogoutResponseSigned` are informational). Encrypted keys must be unencrypted PEM (`*KeyPass` options
  are not supported); signing AuthnRequests uses a self-signed certificate generated for the SP key.
- With `TrustEmailVerified` a SAML `emailVerified` attribute of `"false"` counts as unverified (better-auth
  treats any non-empty string as true).
- Organization data is read through the organization plugin (`plugins.OrganizationStore`).
