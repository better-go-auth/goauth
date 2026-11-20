# OIDC provider plugin

Turns goauth into an OpenID Connect provider (authorization server): other applications send their users
to goauth to sign in, and get an authorization code, access/refresh tokens, an `id_token` and the userinfo
claims. It is the Go version of better-auth's `oidcProvider()` plugin (v1.6.16): same routes, request and
response bodies, RFC 6749 error JSON, cookies and tables, and it works with the better-auth `oidcClient()`
plugin and any OpenID Connect library (tested with `github.com/coreos/go-oidc/v3` + `golang.org/x/oauth2`,
`jose`, and goauth's own generic-oauth plugin as the relying party).

Runnable example: [src/example/oidc-provider](../../example/oidc-provider/main.go)

```sh
go run ./src/example/oidc-provider    # http://localhost:8080, discovery at /.well-known/openid-configuration
go test ./src/example/oidc-provider   # the whole flow end to end
```

## Setup

```go
import (
	oidcprovider "github.com/better-go-auth/goauth/src/plugins/oidc-provider"
	oidcconfig "github.com/better-go-auth/goauth/src/plugins/oidc-provider/config"
)

provider := oidcprovider.New(oidcconfig.Config{
	LoginPage:   "/login",   // required: where signed-out users go (with the authorization query)
	ConsentPage: "/consent", // or GetConsentHTML to render the screen
	TrustedClients: []oidcconfig.Client{{
		ClientID: "internal-app", ClientSecret: "...", Type: oidcconfig.ClientTypeWeb, Name: "Internal",
		RedirectURLs: []string{"https://internal.example.com/callback"}, SkipConsent: true,
	}},
})

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: "https://auth.example.com", Secret: secret},
	Plugins:    []plugin.Plugin{provider},
})
// optional: OpenID Connect libraries look for discovery at <issuer>/.well-known/openid-configuration
mux.Handle("/.well-known/openid-configuration", provider.MetadataHandler())
```

The plugin declares better-auth's tables `oauthApplication`, `oauthAccessToken` and `oauthConsent`
(`plugins.SchemaProvider`); they are created by goauth's migrator in either column case
(`GoAuth.ColumnCase` snake or camel) and are included in `goauth.GenerateSQL` / the CLI.

## The flow

1. The application redirects the browser to `GET /api/auth/oauth2/authorize?response_type=code&client_id=…
   &redirect_uri=…&scope=openid profile email&state=…&nonce=…&code_challenge=…&code_challenge_method=S256`.
2. Without a session goauth redirects to `LoginPage?<the same query>` and stores the query in the signed
   `oidc_login_prompt` cookie. When the login page signs the user in (any sign-in endpoint), an after hook
   resumes the authorization: the sign-in response becomes the next redirect (a browser `fetch`, i.e.
   `Sec-Fetch-Mode: cors`, gets `{"redirect": true, "url": "…"}` instead of a 302).
3. If consent is needed (not a `SkipConsent` trusted client, scopes not consented before, or
   `prompt=consent`) the browser goes to `ConsentPage?consent_code=…&client_id=…&scope=…`; the page posts
   `POST /api/auth/oauth2/consent {"accept": true}` (the consent code is also in the signed
   `oidc_consent_prompt` cookie) and navigates to the returned `redirectURI`.
4. The application exchanges the code: `POST /api/auth/oauth2/token` (form or JSON) with
   `grant_type=authorization_code`, `code`, `redirect_uri`, `code_verifier` and client authentication
   (`client_secret_basic`, `client_secret_post`, or none for public clients with PKCE).
5. `GET /api/auth/oauth2/userinfo` with `Authorization: Bearer <access_token>`; `grant_type=refresh_token`
   (with `offline_access`); `GET|POST /api/auth/oauth2/endsession` for RP-initiated logout.

`prompt=none` (errors `login_required` / `consent_required` at the redirect URI), `prompt=login` and
`max_age` (forces a new login), `nonce`, `state` and PKCE `S256` (`plain` with
`AllowPlainCodeChallengeMethod`) behave as in better-auth.

## Endpoints (under `/api/auth`)

| Method | Path | Notes |
|---|---|---|
| GET | `/.well-known/openid-configuration` | Discovery (`Metadata` overrides keys) |
| GET | `/oauth2/authorize` | Authorization endpoint (optional session) |
| POST | `/oauth2/consent` | `{accept, consent_code?}`, session required → `{redirectURI}` |
| POST | `/oauth2/token` | `authorization_code` / `refresh_token`, RFC 6749 errors `{error, error_description}` |
| GET | `/oauth2/userinfo` | Claims of the token's scopes (+ `GetAdditionalUserInfoClaim`) |
| POST | `/oauth2/register` | RFC 7591 registration: session, or `AllowDynamicClientRegistration` |
| GET | `/oauth2/client/{id}` | `{clientId, name, icon}` for consent screens (session required) |
| GET, POST | `/oauth2/endsession` | `id_token_hint`, `client_id`, `post_logout_redirect_uri`, `state` |

Operation IDs for `DisabledOps`: `getOpenIdConfig`, `oauth2Authorize`, `oauth2Consent`, `oauth2Token`,
`oauth2Userinfo`, `registerOAuthApplication`, `getOAuthClient`, `endSession` (GET), `endSessionPost`.

## Options (`oidcconfig.Config`)

| Field | Default | Meaning |
|---|---|---|
| `LoginPage` | required | Login page URL |
| `ConsentPage` / `GetConsentHTML` | – | Consent page URL, or a function rendering the consent HTML |
| `AccessTokenExpiresIn` / `RefreshTokenExpiresIn` / `CodeExpiresIn` | 1 h / 7 d / 10 min | Lifetimes |
| `Scopes` | – | Extra scopes besides `openid profile email offline_access` |
| `DefaultScope` | `openid` | Scope when the request has none |
| `RequirePKCE` | false | Require `code_challenge` / `code_verifier` |
| `AllowPlainCodeChallengeMethod` | false | Accept `plain` (and a missing method as plain) |
| `AllowDynamicClientRegistration` | false | `/oauth2/register` without a session |
| `GenerateClientID` / `GenerateClientSecret` | 32 random letters | Credential generators |
| `GetAdditionalUserInfoClaim` | – | Extra claims for userinfo and the id_token |
| `TrustedClients` | – | Configured clients (`SkipConsent` skips the consent screen) |
| `StoreClientSecret` | plain | `Mode` plain / hashed (SHA-256, base64url) / encrypted (auth secret), or custom `Hash` / `Encrypt`+`Decrypt` |
| `UseJWTPlugin` | false | Sign id_tokens with the jwt plugin (RS256/EdDSA, JWKS at `/jwks`); requires the jwt plugin |
| `Metadata` | – | Overrides of the discovery document |
| `Schema` | – | Table / column renames per model |

## id_token signing

* Default (HS256): signed with the client secret **as stored** (better-auth's behaviour, so use plain
  storage when relying parties verify the token), and without an `iss` claim — verify it with the issuer
  check disabled (go-oidc: `SkipIssuerCheck`). Clients without a secret (public clients) cannot get an
  HS256 id_token: the exchange fails with 500, as in better-auth; use `UseJWTPlugin` for them.
* `UseJWTPlugin: true`: signed with the jwt plugin's active key; `iss` is the jwt plugin's issuer (or the
  BaseURL), verifiable through `jwks_uri` with any OIDC library.

## Notes and differences from better-auth

* Codes are single use and consumed before the other checks (a failed exchange spends the code).
* Refresh tokens are not rotated away: like better-auth, a refresh issues a new pair and the old refresh
  token stays valid until it expires.
* goauth refuses to start when `UseJWTPlugin` is set without the jwt plugin (better-auth fails at the
  token endpoint).
* Trusted clients are not database rows; on databases enforcing foreign keys (Postgres, MySQL) their tokens
  violate `oauthAccessToken.clientId → oauthApplication.clientId` exactly as in better-auth — insert a
  matching `oauthApplication` row for them there.
