# Social plugin

Sign-in with social providers through OAuth 2.0 / OpenID Connect. It is the Go version of better-auth's
`socialProviders` option and works with the better-auth client's `signIn.social()`, `linkSocial()`,
`getAccessToken()`, `refreshToken()` and `accountInfo()`.

Runnable example: [src/example/social](../../example/social/main.go)

```sh
GITHUB_CLIENT_ID=... GITHUB_CLIENT_SECRET=... go run ./src/example/social   # http://localhost:8080/docs
go test ./src/example/social    # the flow below, end to end, against an in-process fake provider
```

For `go run`, create a GitHub OAuth app with the callback URL
`http://localhost:8080/api/auth/callback/github`. The test runs offline: it uses
[`socialtest`](socialtest/fake_provider.go), a fake OpenID Connect provider with authorize, token, userinfo,
JWKS and discovery endpoints. You can use the same fake in your own tests.

## Setup

```go
import (
	"github.com/better-go-auth/goauth/src/plugins/social"
	socialconfig "github.com/better-go-auth/goauth/src/plugins/social/config"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
)

socialPlugin := social.New(socialconfig.SocialConfig{
	Providers: []providers.Provider{
		providers.GitHub(providers.GitHubOptions{ProviderOptions: providers.ProviderOptions{
			ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
			ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		}}),
	},
	AccountLinking:     socialconfig.AccountLinking{TrustedProviders: []string{"github"}},
	EncryptOAuthTokens: true,
})

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: "http://localhost:8080"}, // redirect_uri = BaseURL + /api/auth/callback/<id>
	Plugins:    []plugin.Plugin{socialPlugin},
})
```

The plugin adds no tables. It stores the provider accounts and their tokens in the core `account` table and
keeps the OAuth state in the `verification` table.

### Providers in the core config (better-auth's `socialProviders`)

Like `betterAuth({ socialProviders, account })`, the providers can live in the core config instead. goauth then
installs the social plugin itself (`goauth.GetPlugin[*social.Plugin](auth, social.PluginID)` still finds it),
configured from `AuthConfig.Account`:

```go
auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn: db,
	AuthConfig: config.AuthConfig{
		BaseURL: "http://localhost:8080",
		SocialProviders: []providers.Provider{
			providers.GitHub(providers.GitHubOptions{ProviderOptions: providers.ProviderOptions{
				ClientID: os.Getenv("GITHUB_CLIENT_ID"), ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
			}}),
		},
		Account: config.AccountOptions{
			AccountLinking:     config.AccountLinkingOptions{TrustedProviders: []string{"github"}},
			EncryptOAuthTokens: true,
			StoreAccountCookie: true, // /account-info without accountId
		},
	},
})
```

Passing `social.New(...)` in `Plugins` as well adds `SocialProviders` to that plugin (its own account options
win); a provider id configured in both places fails setup with a conflict error. Providers of the
generic-oauth plugin are added automatically, like better-auth's `ctx.socialProviders`.

With `Account.StoreAccountCookie` the provider account of the last OAuth sign-in is kept in the encrypted
`account_data` cookie (a JWE with the `better-auth-account` salt, chunked above 4 KB, max-age
`Session.CookieCache.MaxAge` or 300 s): `/account-info` works without `accountId`, `/get-access-token` and
`/refresh-token` use and refresh it, and sign-out deletes it. It is readable by a TypeScript better-auth server
with the same secrets.

The built-in providers are `providers.Google`, `GitHub`, `GitLab`, `Discord`, `Facebook`, `Microsoft` and
`Apple`. `providers.Generic(providers.GenericOptions{ProviderID, Issuer, ProviderOptions{...endpoints}})` covers
any other OpenID Connect provider; the example test uses it with the fake. Every provider takes
`ProviderOptions`:

| Field | Meaning |
|---|---|
| `ClientID` / `ClientSecret` | The OAuth app credentials |
| `Scope` / `DisableDefaultScope` | Extra scopes, or drop the provider's default scopes |
| `RedirectURI` | Overrides `<BaseURL>/api/auth/callback/<id>` |
| `DisableSignUp` / `DisableImplicitSignUp` | Never create users, or create them only when the request sets `requestSignUp` |
| `DisableIDTokenSignIn` | Turn off direct id_token sign-in |
| `OverrideUserInfoOnSignIn` | Copy the provider profile onto the user on every sign-in |
| `MapProfileToUser`, `GetUserInfo`, `RefreshAccessToken`, `VerifyIDToken` | Hooks that replace the default behaviour |
| `AuthorizationEndpoint`, `TokenEndpoint`, `UserInfoEndpoint`, `JWKSEndpoint` | Endpoint overrides |

## Options

| Field | Default | Meaning |
|---|---|---|
| `Providers` | none | The enabled providers |
| `AccountLinking.Enabled` | true | With false, implicit linking and `/link-social` fail |
| `AccountLinking.TrustedProviders` | none | Providers that may link even when they report an unverified email |
| `AccountLinking.AllowDifferentEmails` | false | `/link-social` may link an account whose email differs from the user's |
| `AccountLinking.DisableImplicitLinking` | false | Sign-in never attaches a provider account to an existing user with the same email |
| `AccountLinking.UpdateUserInfoOnLink` | false | Copy the provider profile onto the user when linking |
| `AccountLinking.RequireLocalEmailVerified` | true | Implicit linking requires the local user's email to be verified |
| `EncryptOAuthTokens` | false | Store the provider's access and refresh tokens encrypted with the auth secret |
| `UpdateAccountOnSignIn` | true | Save the new provider tokens on every sign-in |
| `StoreStateStrategy` | `StateDatabase` | `StateDatabase` keeps the state in a verification row plus a signed `state` cookie; `StateCookie` keeps it encrypted in the `oauth_state` cookie |
| `SkipStateCookieCheck` | false | Skip the `state` cookie check, for callbacks that land in another browser (mobile) |
| `ErrorURL` | `<BaseURL>/api/auth/error` | Where callback errors redirect when the request has no `errorCallbackURL` |

The functional options `social.WithProviders`, `WithAccountLinking`, `WithEncryptOAuthTokens` and
`WithStateStrategy` set the same fields.

## Endpoints (under `/api/auth`)

| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/sign-in/social` | `provider`, `callbackURL?`, `newUserCallbackURL?`, `errorCallbackURL?`, `disableRedirect?`, `scopes?`, `loginHint?`, `requestSignUp?`, `idToken?` | Answers `{url, redirect}` with `Location` and the state cookie. With `idToken` it signs the user in directly and answers `{redirect:false, token, user}` |
| GET / POST | `/callback/{id}` | provider's `code`, `state` | Exchanges the code, signs up, signs in or links, sets the session cookie, then 302 |
| POST | `/link-social` | `provider`, `callbackURL?`, `errorCallbackURL?`, `scopes?`, `disableRedirect?`, `idToken?` | Requires a session. Same `{url, redirect}` answer; the callback links the account instead of signing in |
| POST | `/get-access-token` | `providerId`, `accountId?`, `userId?` | A valid provider access token, refreshed when it has expired |
| POST | `/refresh-token` | `providerId`, `accountId?`, `userId?` | Forces a refresh with the stored refresh token |
| GET | `/account-info` | query `accountId?`, `providerId?` | The provider's profile for an account |
| GET | `/list-accounts` | | Core route. The user's accounts (`credential`, `github`, ...) |
| POST | `/unlink-account` | `providerId`, `accountId?` | Core route |

The `callbackURL`, `newUserCallbackURL` and `errorCallbackURL` values must be relative paths or trusted
origins. After the callback, a new user goes to `newUserCallbackURL` and a returning user goes to `callbackURL`
(by default `BaseURL`).

## Flow

```sh
# 1. start: answers {"url":"https://github.com/login/oauth/authorize?...","redirect":true} and sets the state cookie
curl -c jar -b jar -H 'Origin: http://localhost:8080' -H 'Content-Type: application/json' \
  -d '{"provider":"github","callbackURL":"/dashboard","newUserCallbackURL":"/welcome"}' \
  http://localhost:8080/api/auth/sign-in/social

# 2. open the url in the browser that holds the cookies. GitHub redirects to
#    /api/auth/callback/github?code=...&state=..., which sets the session cookie and redirects to /welcome.

# 3. the session cookie opens your own protected routes
curl -b jar http://localhost:8080/api/example/me
curl -b jar http://localhost:8080/api/auth/list-accounts

# 4. a signed-in (e.g. email/password) user links GitHub: same redirect dance, back to /settings
curl -c jar -b jar -H 'Origin: http://localhost:8080' -H 'Content-Type: application/json' \
  -d '{"provider":"github","callbackURL":"/settings"}' http://localhost:8080/api/auth/link-social
```

Browsers do steps 1 and 2 by themselves: `signIn.social({ provider: "github" })` in the better-auth client.

## Errors

Errors from the JSON endpoints:

| Status / code | When |
|---|---|
| 404 `PROVIDER_NOT_FOUND` | `provider` is not configured |
| 403 `INVALID_CALLBACK_URL` / `INVALID_ERROR_CALLBACK_URL` / `INVALID_NEW_USER_CALLBACK_URL` | A redirect target is not trusted |
| 401 `UNAUTHORIZED` | `/link-social` without a session |
| 401 `INVALID_TOKEN` | `idToken` sign-in with a bad token |
| 401 `LINKING_NOT_ALLOWED` / `LINKING_DIFFERENT_EMAILS_NOT_ALLOWED` | `idToken` linking refused |
| 400 `FAILED_TO_GET_ACCESS_TOKEN`, `REFRESH_TOKEN_NOT_FOUND`, `FAILED_TO_REFRESH_ACCESS_TOKEN`, `TOKEN_REFRESH_NOT_SUPPORTED`, `ACCESS_TOKEN_NOT_FOUND` | The account token endpoints |

The callback always answers with a redirect: to `errorCallbackURL`, or to `ErrorURL`, with `?error=<code>`.

| `error` | When |
|---|---|
| `state_not_found`, `state_mismatch`, `state_invalid` | The state is missing, expired, or not from this browser |
| the provider's code (e.g. `access_denied`), `no_code`, `invalid_code` | The provider refused, or the code exchange failed |
| `unable_to_get_user_info`, `email_not_found` | The provider sent no usable profile |
| `account_not_linked` | Implicit linking was refused (the email is unverified, or linking is off) |
| `signup_disabled` | A new user, with `DisableSignUp` or `DisableImplicitSignUp` set |
| `email_doesn't_match`, `unable_to_link_account`, `account_already_linked_to_different_user` | `/link-social` was refused |

## Notes

- The generic-oauth plugin's providers are social providers automatically (`/sign-in/social`,
  `/get-access-token`, ...); their redirect URI is `/oauth2/callback/<id>`, as in better-auth.
- Encrypted tokens and the OAuth state cookie use `AuthConfig.Secrets` when set: new data is written as a
  `$ba$<version>$` envelope with the current secret, older versions still decrypt.
- The provider account's `accountId` is the provider's user id (`sub`).
- `/list-accounts` returns a `scopes` array for each account.
