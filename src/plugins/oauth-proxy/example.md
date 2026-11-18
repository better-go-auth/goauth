# OAuth-proxy plugin

Social sign-in on deployments whose URL is not registered at the OAuth provider, such as preview
deployments (`https://my-app-git-feature.vercel.app`). The provider only knows production's callback
(`https://my-app.com/api/auth/callback/github`). A preview sends the provider's callback to production.
Production finishes the code exchange and sends the user's profile back to the preview, encrypted. The
preview then signs the user in. It is the Go version of better-auth's `oAuthProxy()` plugin. Its state
packages and profiles use better-auth's encryption, so a goauth preview can proxy through a better-auth
production deployment and the other way round, as long as they share the secret.

Runnable example: [src/example/oauth-proxy](../../example/oauth-proxy/main.go)

```sh
go run ./src/example/oauth-proxy     # production on http://localhost:8080
PORT=8081 BASE_URL=http://localhost:8081 PRODUCTION_URL=http://localhost:8080 SQLITE_DB=preview.db \
  go run ./src/example/oauth-proxy   # a preview proxying through it
go test ./src/example/oauth-proxy    # the whole preview flow against a fake provider
```

## Setup

Install the same configuration on production and on every preview, with the same secret, next to the
social plugin:

```go
import (
	oauthproxy "github.com/better-go-auth/goauth/src/plugins/oauth-proxy"
	proxyconfig "github.com/better-go-auth/goauth/src/plugins/oauth-proxy/config"
	"github.com/better-go-auth/goauth/src/plugins/social"
)

socialPlugin := social.New(socialconfig.SocialConfig{Providers: []providers.Provider{github}})
proxy := oauthproxy.New(proxyconfig.OAuthProxyConfig{
	ProductionURL: "https://my-app.com",
}, oauthproxy.WithSocial(socialPlugin))

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: os.Getenv("BASE_URL"), Secret: os.Getenv("BETTER_AUTH_SECRET")},
	Plugins:    []plugin.Plugin{socialPlugin, proxy},
})
```

`WithSocial` is required (startup fails without it, and the plugin declares a dependency on `social`).
The proxy uses the social plugin's providers, OAuth state and account-linking policy. Generic OAuth
providers passed to `social.WithProviders` work too. Previews must trust their own origin, which is the
default when `BaseURL` is the preview URL. The plugin has no table.

## Options

| Field | Default | Meaning |
|---|---|---|
| `ProductionURL` | `$BETTER_AUTH_URL`, else `BaseURL` | The production deployment. A request whose origin is production skips the proxy |
| `CurrentURL` | the request URL | This deployment's URL. Without it, the request URL is used, then `VERCEL_URL`, `NETLIFY_URL`, `RENDER_URL`, ..., then the base URL. The request scheme comes from `X-Forwarded-Proto`, else from `BaseURL` when the host matches, else `http` |
| `MaxAge` | 60 s | How long production's encrypted profile is accepted |
| `Secret` | the auth secret | Encrypts state packages and profiles. Production and previews must share it |

Functional options: `WithProductionURL`, `WithCurrentURL`, `WithMaxAge`, `WithSecret`,
`WithSocial`, `WithSocialService`.

## Endpoints and hooks (under `/api/auth`)

| Method | Path | Notes |
|---|---|---|
| GET | `/oauth-proxy-callback?callbackURL=&profile=` | Operation `oauthProxyCallback`. `callbackURL` is required and must be trusted (403 `INVALID_CALLBACK_URL`). It decrypts the profile, signs the user in or up, sets the session cookie and redirects to `callbackURL`, or to `newUserCallbackURL` for new users |

The plugin also hooks the social routes:

- Before `/sign-in/social` and `/sign-in/oauth2` (unless skipped): `callbackURL` becomes
  `<current origin>/api/auth/oauth-proxy-callback?callbackURL=<original>`. With `ProductionURL`, the
  request's base URL becomes production's, so the provider's `redirect_uri` is production's callback.
- After `/sign-in/social` and `/sign-in/oauth2`: the `state` in the returned `url` is replaced by an
  encrypted state package (the original state plus this deployment's encrypted state payload). Like
  better-auth, only the body's `url` changes. The `Location` header keeps the original URL.
- Before `/callback/{id}` (production): a state package is decrypted and checked. Production exchanges
  the code with the preview's PKCE verifier and redirects to the preview's `/oauth-proxy-callback` with
  `profile=<encrypted payload>`. Any other state goes through the normal callback.
- After `/callback/{id}`: if a normal callback redirects to production's own
  `/oauth-proxy-callback?callbackURL=...`, the browser is sent straight to the inner `callbackURL`.

Send `x-skip-oauth-proxy: 1` to make a sign-in skip the proxy.

## Flow

```sh
# 1. on the preview: start the sign-in
curl -c jar -H 'Origin: https://preview.my-app.com' -H 'Content-Type: application/json' \
  -d '{"provider":"github","callbackURL":"/dashboard","disableRedirect":true}' \
  https://preview.my-app.com/api/auth/sign-in/social
# {"url":"https://github.com/login/oauth/authorize?...&redirect_uri=https%3A%2F%2Fmy-app.com%2Fapi%2Fauth%2Fcallback%2Fgithub&state=<encrypted package>","redirect":false}

# 2. the provider redirects the browser to production:
#    https://my-app.com/api/auth/callback/github?code=...&state=<encrypted package>
#    production answers 302 https://preview.my-app.com/api/auth/oauth-proxy-callback?callbackURL=%2Fdashboard&profile=<encrypted>

# 3. the preview signs the user in: 302 /dashboard with the session cookie
curl -b jar -c jar -i 'https://preview.my-app.com/api/auth/oauth-proxy-callback?callbackURL=%2Fdashboard&profile=...'
```

## Errors

Every outcome of the callbacks is a 302 to an error URL with `?error=<code>`. The proxy callback uses the
payload's `errorURL` (the sign-in's `errorCallbackURL`), else `OnAPIError.ErrorURL`, else
`<BaseURL>/api/auth/error`. Production's callback hook uses the state's `errorURL`, else
`OnAPIError.ErrorURL`, else `<base URL>/error`.

| Code | Where | When |
|---|---|---|
| `missing_profile` | proxy callback | No `profile` parameter |
| `invalid_profile` | proxy callback | The profile does not decrypt (tampered, or a different secret) |
| `invalid_payload` | proxy callback | Not JSON, or `timestamp` / `userInfo` / `account` / `callbackURL` missing |
| `payload_expired` | proxy callback | Older than `MaxAge`, or more than 10 s in the future |
| `signup_disabled`, `account_not_linked`, ... | proxy callback | better-auth's `handleOAuthUserInfo` errors with spaces replaced by `_` |
| `<CODE>` + `error_description` | proxy callback | A hook refused the sign-in, e.g. `BANNED_USER` |
| `user_creation_failed` | proxy callback | No session was created |
| `state_mismatch` | production callback | The package's state does not match the state payload |
| `<provider error>` | production callback | The provider reported an error, e.g. `access_denied` |
| `no_code`, `oauth_provider_not_found`, `invalid_code`, `unable_to_get_user_info`, `email_not_found` | production callback | As in the normal OAuth callback |

## Notes

- Production never creates a user or a session for proxied sign-ins. It only relays the provider's
  answer, so the preview database gets the user and account.
- The preview's OAuth state (verification row or `oauth_state` cookie) is consumed at the proxy callback.
  The signed `state` cookie is not required there, because the request comes back through production.
- better-auth only proxies the social `/callback/{id}` route. Generic OAuth providers configured with
  their own `/oauth2/callback/{providerId}` redirect URI are not proxied. Register them through
  `social.WithProviders` to use the social callback.
- The state strategy is detected from the sign-in response: an `oauth_state` cookie means the cookie
  strategy, otherwise the verification row is read.
