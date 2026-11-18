# Email OTP plugin

Sends one-time codes by email. Users can sign in with a code (and are signed up if they are new),
verify their email address, reset their password, and change their email. It is the Go version of
better-auth's `emailOTP()` plugin and works with the better-auth `emailOTPClient()` plugin.

Runnable example: [src/example/email-otp](../../example/email-otp/main.go)

```sh
go run ./src/example/email-otp     # server on http://localhost:8080. Codes are printed to the log
go test ./src/example/email-otp    # runs the flows below end to end
```

## Setup

```go
import (
	emailotp "github.com/better-go-auth/goauth/src/plugins/email-otp"
	emailotpconfig "github.com/better-go-auth/goauth/src/plugins/email-otp/config"
)

otpPlugin := emailotp.New(emailotpconfig.EmailOTPConfig{
	// required: deliver the code. data.Type is "sign-in", "email-verification", "forget-password" or "change-email"
	SendVerificationOTP: func(data emailotpconfig.SendVerificationOTPData, r *http.Request) error {
		return mailer.Send(data.Email, "Your code", data.OTP)
	},
	SendVerificationOnSignUp: true, // email/password sign-ups get an "email-verification" code
})

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: "http://localhost:8080"},
	Plugins:    []plugin.Plugin{otpPlugin},
})
```

The plugin has no tables of its own. Codes are stored in the core `verification` table as `code:attempts`.

## Options (`EmailOTPConfig`)

| Field | Default | Meaning |
|---|---|---|
| `SendVerificationOTP` | none (required) | Sends the code. Without it, send endpoints fail with 500 `SENDER_NOT_CONFIGURED` |
| `OtpLength` | 6 | Number of digits |
| `ExpiresIn` | 5 min | How long a code is valid |
| `AllowedAttempts` | 3 | Wrong guesses allowed before the code is deleted (`TOO_MANY_ATTEMPTS`) |
| `GenerateOTP` | random digits | Custom generator. Returning `""` falls back to the default |
| `SendVerificationOnSignUp` | false | Send an `email-verification` code after email/password sign-up |
| `OverrideDefaultEmailVerification` | false | Send an OTP instead of the core verification link, on sign-up and from core verification emails |
| `DisableSignUp` | false | `/sign-in/email-otp` won't create users. Unknown addresses get no code |
| `StoreOTP` | `{Mode: "plain"}` | `"hashed"`, `"encrypted"`, or custom `Hash` / `Encrypt`+`Decrypt` |
| `ResendStrategy` | `"rotate"` | `"reuse"` resends the current code if it is still valid (not possible with hashed storage) |
| `ChangeEmail` | disabled | `{Enabled, VerifyCurrentEmail}` for the change-email endpoints |
| `RateLimit` | 3 requests / 60s | Plugin rules (better-auth's) for every OTP endpoint, per client IP and path. Enforced by goauth's global limiter, so only while `AuthConfig.RateLimit` is enabled (default: production only). `Enabled: false` drops the plugin rules |

Each field also has a functional option, for example `emailotp.WithAllowedAttempts(5)` or
`emailotp.WithRateLimit(time.Minute, 3)`.

## Endpoints (under `/api/auth`)

| Method | Path | Body | Response |
|---|---|---|---|
| POST | `/email-otp/send-verification-otp` | `email`, `type` (`sign-in` \| `email-verification` \| `forget-password`) | `{success}` |
| POST | `/email-otp/check-verification-otp` | `email`, `type`, `otp` | `{success}`. Checks a code without using it up. Registered users only |
| POST | `/sign-in/email-otp` | `email`, `otp`, `name?`, `image?` | `{token, user}` and a session cookie. Creates the user if needed, with `emailVerified: true` |
| POST | `/email-otp/verify-email` | `email`, `otp` | `{status, token, user}`. `token` is only set with `EmailVerification.AutoSignInAfterVerification` |
| POST | `/email-otp/request-password-reset` | `email` | `{success}` (deprecated alias: `/forget-password/email-otp`) |
| POST | `/email-otp/reset-password` | `email`, `otp`, `password` | `{status}` |
| POST | `/email-otp/request-email-change` | `newEmail`, `otp?` | `{success}`. Needs a session and `ChangeEmail.Enabled` |
| POST | `/email-otp/change-email` | `newEmail`, `otp` | `{success}`. Needs a session |

Send endpoints don't reveal whether an address is registered. For `email-verification` and
`forget-password` (and for `sign-in` with `DisableSignUp`), an unknown address gets `{success: true}`
but no email.

## Flow

```sh
H='-H Origin:http://localhost:8080 -H Content-Type:application/json'

# 1. sign in (or sign up) with a code: request it, then read it from the server log
curl $H -d '{"email":"otto@example.com","type":"sign-in"}' http://localhost:8080/api/auth/email-otp/send-verification-otp
curl -c jar $H -d '{"email":"otto@example.com","otp":"123456","name":"Otto"}' http://localhost:8080/api/auth/sign-in/email-otp
curl -b jar http://localhost:8080/api/example/me

# 2. verify the email of an email/password user (the code is sent on sign-up)
curl $H -d '{"email":"vera@example.com","password":"Password123!","name":"Vera"}' http://localhost:8080/api/auth/sign-up/email
curl $H -d '{"email":"vera@example.com","otp":"123456"}' http://localhost:8080/api/auth/email-otp/verify-email

# 3. reset a forgotten password
curl $H -d '{"email":"vera@example.com"}' http://localhost:8080/api/auth/email-otp/request-password-reset
curl $H -d '{"email":"vera@example.com","otp":"123456","password":"NewPassword456!"}' http://localhost:8080/api/auth/email-otp/reset-password
```

## Errors

| Code | Status | When |
|---|---|---|
| `INVALID_OTP` | 400 | Wrong, missing, used or deleted code. Each wrong guess counts as an attempt |
| `OTP_EXPIRED` | 400 | The code is older than `ExpiresIn` |
| `TOO_MANY_ATTEMPTS` | 403 | `AllowedAttempts` wrong guesses. The code is deleted, so request a new one |
| `INVALID_EMAIL` | 400 | Malformed address on a send endpoint |
| `USER_NOT_FOUND` | 400 | `check-verification-otp` for an unregistered address |
| `PASSWORD_TOO_SHORT` / `PASSWORD_TOO_LONG` | 400 | `reset-password` outside `EmailAndPassword.Min/MaxPasswordLength` (8..128). Checked before the code |
| (no code) | 429 | Rate limit hit: better-auth's `{"message":"Too many requests. Please try again later."}` with `X-Retry-After` |
| `CHANGE_EMAIL_DISABLED`, `EMAIL_IS_THE_SAME`, `EMAIL_ALREADY_IN_USE`, `CURRENT_EMAIL_OTP_REQUIRED` | 400 | Change-email endpoints |

## Notes

- Codes are single use. Requesting a new code replaces the previous one (with the `"rotate"` strategy).
- `/email-otp/request-email-change` and `/email-otp/change-email` run behind better-auth's
  `sensitiveSessionMiddleware`: the session is read from the session store, never from the cookie cache, so a
  revoked session that is still cached in `session_data` gets 401 `UNAUTHORIZED`.
- With `StoreOTP` `"encrypted"` the codes are encrypted with the current `AuthConfig.Secrets` version.
- A successful OTP sign-in also marks an existing user's email as verified. Banned users (admin plugin) get 403 `BANNED_USER` (like better-auth).
- An OTP-created user has no password. They can set one with the password reset flow, which creates
  the credential account.
- To protect your own routes, see the "Protecting your own routes" section in
  [the username example](../username/example.md#protecting-your-own-routes).
