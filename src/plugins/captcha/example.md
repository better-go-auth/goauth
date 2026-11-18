# Captcha plugin

Protects sign-up, sign-in and password-reset requests with a captcha. It is the Go version of better-auth's
`captcha()` plugin and supports Cloudflare Turnstile, Google reCAPTCHA (v2 and v3 with a minimum score),
hCaptcha and CaptchaFox. better-auth has no captcha client plugin: the browser sends the widget's token in the
`x-captcha-response` header.

Runnable example: [src/example/captcha](../../example/captcha/main.go)

```sh
TURNSTILE_SECRET_KEY=... go run ./src/example/captcha   # server on http://localhost:8080
go test ./src/example/captcha                            # the flow below, against a fake Turnstile
```

## Setup

```go
import (
	"github.com/better-go-auth/goauth/src/plugins/captcha"
	captchaconfig "github.com/better-go-auth/goauth/src/plugins/captcha/config"
)

captchaPlugin := captcha.New(captchaconfig.CaptchaConfig{
	Provider:  captchaconfig.CloudflareTurnstile,
	SecretKey: os.Getenv("TURNSTILE_SECRET_KEY"),
})

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: "http://localhost:8080"},
	Plugins:    []plugin.Plugin{captchaPlugin},
})
```

The plugin has no routes and no tables.

## Options

| Field | Default | Meaning |
|---|---|---|
| `Provider` | required | `cloudflare-turnstile`, `google-recaptcha`, `hcaptcha` or `captchafox` |
| `SecretKey` | required | Provider secret. Missing: protected requests answer `500 UNKNOWN_ERROR` |
| `Endpoints` | `/sign-up/email`, `/sign-in/email`, `/request-password-reset` | Protected endpoints (substring match on the path after `BasePath`) |
| `SiteVerifyURLOverride` | provider URL | Verification endpoint (self-hosted or test servers) |
| `MinScore` | 0.5 | reCAPTCHA v3 minimum score (responses without a score only need `success`) |
| `SiteKey` | none | Sent as `sitekey` to hCaptcha and CaptchaFox |
| `HTTPClient` | 30 s timeout | Client for the verification call |

`/sign-in/email-otp` contains `/sign-in/email` but is exempt unless you list it in `Endpoints`.

## Flow

```sh
# no token
curl -i -X POST localhost:8080/api/auth/sign-up/email -H 'Content-Type: application/json' \
  -d '{"email":"a@example.com","password":"Password123!","name":"A"}'
# 400 {"message":"Missing CAPTCHA response","code":"MISSING_RESPONSE"}

# with the widget token
curl -i -X POST localhost:8080/api/auth/sign-up/email -H 'Content-Type: application/json' \
  -H 'x-captcha-response: <token>' -d '{"email":"a@example.com","password":"Password123!","name":"A"}'
```

With the official client:

```ts
await authClient.signUp.email(
  { email, password, name },
  { headers: { "x-captcha-response": turnstileToken } },
);
```

## Errors

Captcha errors are better-auth's `middlewareResponse`: a JSON body `{"message","code"}` sent with
`Content-Type: text/plain;charset=UTF-8`.

| Status | Code | Message |
|---|---|---|
| 400 | `MISSING_RESPONSE` | Missing CAPTCHA response |
| 403 | `VERIFICATION_FAILED` | Captcha verification failed |
| 500 | `UNKNOWN_ERROR` | Something went wrong (missing secret key, provider unreachable or answering an error; the cause is logged) |

## Notes

- Like better-auth's `onRequest`, the check runs before everything else: before the rate limiter, the origin
  check and body validation. Rejected requests are not counted by the rate limiter.
- The client IP sent to the provider (`remoteip`, `remoteIp` for CaptchaFox) is resolved like the rate
  limiter's: `Advanced.IPAddress.Headers` (default `x-forwarded-for`), then the connection address.
  better-auth sends `127.0.0.1` in development instead of the connection address.
- Turnstile gets a JSON body; the other providers get a form body, as in better-auth.
