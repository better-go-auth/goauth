# Generic OAuth plugin

Sign-in with any OAuth 2.0 / OpenID Connect provider, such as Keycloak, Okta, Auth0, Entra ID, or your own
identity provider. It is the Go version of better-auth's `genericOAuth()` plugin and works with the
better-auth `genericOAuthClient()` (`signIn.oauth2()`, `oauth2.link()`).

Runnable example: [src/example/generic-oauth](../../example/generic-oauth/main.go)

```sh
OAUTH_DISCOVERY_URL=https://idp.example.com/.well-known/openid-configuration \
OAUTH_CLIENT_ID=... OAUTH_CLIENT_SECRET=... go run ./src/example/generic-oauth   # http://localhost:8080/docs
go test ./src/example/generic-oauth   # the flow below, end to end, against an in-process fake provider
```

The example's provider id is `my-idp`, so register
`http://localhost:8080/api/auth/oauth2/callback/my-idp` as the redirect URI at the provider. The test runs
offline. It configures the provider from the discovery document of the social plugin's fake provider,
[`socialtest`](../social/socialtest/fake_provider.go).

## Setup

```go
import (
	genericoauth "github.com/better-go-auth/goauth/src/plugins/generic-oauth"
	goconfig "github.com/better-go-auth/goauth/src/plugins/generic-oauth/config"
	gproviders "github.com/better-go-auth/goauth/src/plugins/generic-oauth/providers"
)

oauthPlugin := genericoauth.New(goconfig.Config{
	Providers: []goconfig.ProviderConfig{
		{
			ProviderID:   "my-idp",
			DiscoveryURL: os.Getenv("OAUTH_DISCOVERY_URL"),
			ClientID:     os.Getenv("OAUTH_CLIENT_ID"),
			ClientSecret: os.Getenv("OAUTH_CLIENT_SECRET"),
			Scopes:       []string{"openid", "email", "profile"},
			PKCE:         true,
		},
		// presets fill in the endpoints and scopes
		gproviders.Keycloak(gproviders.IssuerOptions{
			Issuer:        "https://kc.example.com/realms/main",
			PresetOptions: gproviders.PresetOptions{ClientID: id, ClientSecret: secret, PKCE: true},
		}),
	},
	EncryptOAuthTokens: true,
})

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: "http://localhost:8080"}, // redirect_uri = BaseURL + /api/auth/oauth2/callback/<id>
	Plugins:    []plugin.Plugin{oauthPlugin},
})
```

The plugin adds no tables. It uses the core `account` and `verification` tables. The state, PKCE, account
linking and token storage code is shared with the [social plugin](../social/example.md).

The presets in `generic-oauth/providers` are `Auth0`, `Keycloak`, `Okta`, `MicrosoftEntraID`, `Slack`, `Line`,
`HubSpot`, `Patreon` and `Gumroad`.

## Options

`ProviderConfig` describes one provider:

| Field | Default | Meaning |
|---|---|---|
| `ProviderID` | required | Stored on accounts and used in `/oauth2/callback/{providerId}` |
| `DiscoveryURL` | none | OIDC discovery document. Its endpoints win over the URLs below |
| `AuthorizationURL` / `TokenURL` / `UserInfoURL` | none | Explicit endpoints when there is no discovery document |
| `ClientID` / `ClientSecret` | required | OAuth client credentials |
| `Scopes` | none | Requested on every authorization |
| `PKCE` | false | Send an S256 `code_challenge` and the `code_verifier` |
| `Issuer` / `RequireIssuerValidation` | the discovery issuer / false | RFC 9207 check of the callback's `iss` |
| `RedirectURI` | `<BaseURL>/api/auth/oauth2/callback/<id>` | Overrides the redirect URI |
| `Prompt`, `AccessType`, `ResponseType`, `ResponseMode` | none | Authorization request parameters |
| `AuthorizationURLParams(Func)`, `TokenURLParams(Func)` | none | Extra request parameters |
| `Authentication` | `providers.AuthPost` | Client authentication at the token endpoint (`AuthPost` or `AuthBasic`) |
| `GetToken`, `GetUserInfo`, `MapProfileToUser` | none | Replace the code exchange or the profile lookup, or map the profile |
| `DisableSignUp` / `DisableImplicitSignUp` | false | Never create users, or create them only when the request sets `requestSignUp` |
| `OverrideUserInfo` | false | Copy the provider profile onto the user on every sign-in |
| `DiscoveryHeaders`, `AuthorizationHeaders`, `HTTPClient` | none | HTTP settings |

`Config` holds the provider list and the plugin-wide options:

| Field | Default | Meaning |
|---|---|---|
| `AccountLinking` | linking on | The social plugin's `socialconfig.AccountLinking` (trusted providers, different emails, ...) |
| `EncryptOAuthTokens` | false | Store the provider tokens encrypted with the auth secret |
| `UpdateAccountOnSignIn` | true | Save the new provider tokens on every sign-in |
| `StoreStateStrategy` / `SkipStateCookieCheck` | database / false | Where the OAuth state lives, as in the social plugin |
| `ErrorURL` | `<BaseURL>/api/auth/error` | Where callback errors redirect when the request has no `errorCallbackURL` |
| `DiscoveryCacheTTL` | 10m | Discovery document cache (negative disables it) |

## Endpoints (under `/api/auth`)

| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/sign-in/oauth2` | `providerId`, `callbackURL?`, `newUserCallbackURL?`, `errorCallbackURL?`, `disableRedirect?`, `scopes?`, `requestSignUp?`, `additionalData?` | Answers `{url, redirect}` and sets the state cookie |
| GET | `/oauth2/callback/{providerId}` | provider's `code`, `state`, `iss?` | Exchanges the code, signs up, signs in or links, sets the session cookie, then 302 |
| POST | `/oauth2/link` | `providerId`, `callbackURL`, `errorCallbackURL?`, `scopes?` | Requires a session. Answers `{url, redirect:true}`; the callback links the account to the user |
| GET | `/list-accounts` | | Core route. Lists the user's accounts (`credential`, `my-idp`, ...) |

New users go to `newUserCallbackURL` and returning users go to `callbackURL` (by default `BaseURL`). The
callback URLs must be relative paths or trusted origins.

## Flow

```sh
# 1. start: answers {"url":"https://idp.example.com/authorize?...","redirect":true} and sets the state cookie
curl -c jar -b jar -H 'Origin: http://localhost:8080' -H 'Content-Type: application/json' \
  -d '{"providerId":"my-idp","callbackURL":"/dashboard","newUserCallbackURL":"/welcome"}' \
  http://localhost:8080/api/auth/sign-in/oauth2

# 2. open the url in the browser that holds the cookies. The IdP redirects to
#    /api/auth/oauth2/callback/my-idp?code=...&state=..., which sets the session cookie and redirects to /welcome.

# 3. the session cookie opens your own protected routes
curl -b jar http://localhost:8080/api/example/me

# 4. a signed-in (e.g. email/password) user links the IdP account: same redirect dance, back to /settings
curl -c jar -b jar -H 'Origin: http://localhost:8080' -H 'Content-Type: application/json' \
  -d '{"providerId":"my-idp","callbackURL":"/settings"}' http://localhost:8080/api/auth/oauth2/link
```

## Errors

Errors from the JSON endpoints:

| Status / code | When |
|---|---|
| 400 `PROVIDER_CONFIG_NOT_FOUND` | `/sign-in/oauth2` or the callback with an unknown `providerId` |
| 404 `PROVIDER_NOT_FOUND` | `/oauth2/link` with an unknown `providerId` |
| 400 `INVALID_OAUTH_CONFIGURATION` | No authorization or token endpoint (and no discovery document) |
| 403 `INVALID_CALLBACK_URL` / `INVALID_ERROR_CALLBACK_URL` / `INVALID_NEW_USER_CALLBACK_URL` | A redirect target is not trusted |
| 401 `UNAUTHORIZED` | `/oauth2/link` without a session |

The callback redirects to `errorCallbackURL`, or to `ErrorURL`, with `?error=<code>`:

| `error` | When |
|---|---|
| the provider's code (e.g. `access_denied`), `oAuth_code_missing` | The provider refused, or sent no code. These always go to `ErrorURL` |
| `state_not_found`, `state_mismatch`, `state_invalid` | The state is missing, expired, or not from this browser |
| `issuer_mismatch`, `issuer_missing` | The RFC 9207 `iss` check failed |
| `oauth_code_verification_failed` | The token endpoint rejected the code |
| `user_info_is_missing`, `email_is_missing`, `id_is_missing`, `name_is_missing` | The profile is incomplete |
| `account_not_linked`, `signup_disabled` | Implicit linking or sign-up was refused |
| `email_doesn't_match`, `unable_to_link_account`, `account_already_linked_to_different_user` | `/oauth2/link` was refused |

## Notes

- Unlike `/link-social`, `/oauth2/link` does not check whether the provider has verified the email. This
  matches better-auth.
- Like better-auth, these providers are also social providers: goauth installs the social plugin (or adds
  them to the one you pass, unless it already has a provider with the same id), so `/sign-in/social`,
  `/link-social`, `/get-access-token`, `/refresh-token` and `/account-info` work with them. Those flows come
  back to `/oauth2/callback/{providerId}` (the redirect URI better-auth uses), handled by this plugin.
