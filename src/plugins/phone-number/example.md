# Phone number plugin

Verifies phone numbers with SMS codes. Users can sign up on their first verification, sign in with
phone number and password, and reset their password by SMS. It is the Go version of better-auth's
`phoneNumber()` plugin and works with the better-auth `phoneNumberClient()` plugin.

Runnable example: [src/example/phone-number](../../example/phone-number/main.go)

```sh
go run ./src/example/phone-number     # server on http://localhost:8080. SMS codes are printed to the log
go test ./src/example/phone-number    # runs the flows below end to end
```

## Setup

```go
import (
	phonenumber "github.com/better-go-auth/goauth/src/plugins/phone-number"
	phoneconfig "github.com/better-go-auth/goauth/src/plugins/phone-number/config"
)

phonePlugin := phonenumber.New(phoneconfig.PhoneNumberConfig{
	SendOTP: func(data phoneconfig.OTPData, r *http.Request) error {
		return sms.Send(data.PhoneNumber, "Your code: "+data.Code)
	},
	SendPasswordResetOTP: func(data phoneconfig.OTPData, r *http.Request) error {
		return sms.Send(data.PhoneNumber, "Reset code: "+data.Code)
	},
	PhoneNumberValidator: func(p string) bool { return e164.MatchString(p) },
	// verifying an unknown number creates the user (email is required, so it gets a placeholder)
	SignUpOnVerification: &phoneconfig.SignUpOnVerification{
		GetTempEmail: func(p string) string { return strings.TrimPrefix(p, "+") + "@phone.example.com" },
	},
})

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: "http://localhost:8080"},
	Plugins:    []plugin.Plugin{phonePlugin},
})
```

The `phoneNumber` (unique) and `phoneNumberVerified` columns are part of the core user table, so the
plugin has no migrator. Codes are stored in the core `verification` table as `code:attempts`. The
identifier is the phone number, or `<phone>-request-password-reset` for reset codes.

## Options (`PhoneNumberConfig`)

| Field | Default | Meaning |
|---|---|---|
| `SendOTP` | none | Sends verification codes. Without it `send-otp` answers 501 `SEND_OTP_NOT_IMPLEMENTED` |
| `SendPasswordResetOTP` | none | Sends password reset codes. Without it the code is stored but not sent |
| `VerifyOTP` | built-in | Replaces the code check, e.g. with Twilio Verify. Returns `(ok, err)` |
| `PhoneNumberValidator` | none | Rejects numbers on `send-otp` and `sign-in/phone-number` with `INVALID_PHONE_NUMBER` |
| `OTPLength` | 6 | Number of digits |
| `ExpiresIn` | 300s | How long a code is valid |
| `AllowedAttempts` | 3 | Wrong guesses allowed before `TOO_MANY_ATTEMPTS` |
| `RequireVerification` | false | Password sign-in of an unverified number fails with `PHONE_NUMBER_NOT_VERIFIED`, and a new code is sent |
| `SignUpOnVerification` | nil (off) | Create users for unknown numbers on verify. `GetTempEmail` (default `<phone>@phone.invalid`) and `GetTempName` (default the number) |
| `CallbackOnVerification` | none | Runs after every successful verification. An error aborts the request |

Each field also has a functional option, for example `phonenumber.WithOTPLength(4)` or
`phonenumber.WithRequireVerification(true)`.

## Endpoints (under `/api/auth`)

| Method | Path | Body | Response |
|---|---|---|---|
| POST | `/phone-number/send-otp` | `phoneNumber` | `{message: "code sent"}` |
| POST | `/phone-number/verify` | `phoneNumber`, `code`, `disableSession?`, `updatePhoneNumber?`, extra user fields | `{status, token, user}` and a session cookie |
| POST | `/sign-in/phone-number` | `phoneNumber`, `password`, `rememberMe?` | `{token, user}` and a session cookie |
| POST | `/phone-number/request-password-reset` | `phoneNumber` | `{status: true}`, also for unknown numbers (they get no SMS) |
| POST | `/phone-number/reset-password` | `phoneNumber`, `otp`, `newPassword` | `{status: true}` |

`verify` has three outcomes:

- If the number belongs to a user, it is marked verified and the user is signed in.
- If the number is unknown and `SignUpOnVerification` is set, a user is created and signed in.
- With `updatePhoneNumber: true` and a session, the number is attached to the signed-in user, and
  `token` is the current session's token.

`disableSession: true` skips the session (`token: null`).

The phone number **can't be changed with `/update-user`**. A body with `phoneNumber` gets 400
`PHONE_NUMBER_CANNOT_BE_UPDATED`. Change it by verifying a code with `updatePhoneNumber: true`.

## Flow

```sh
H='-H Origin:http://localhost:8080 -H Content-Type:application/json'

# 1. send a code, then verify it: an unknown number is signed up and signed in
curl $H -d '{"phoneNumber":"+15550001234"}' http://localhost:8080/api/auth/phone-number/send-otp
curl -c jar $H -d '{"phoneNumber":"+15550001234","code":"123456"}' http://localhost:8080/api/auth/phone-number/verify
curl -b jar http://localhost:8080/api/example/me

# 2. a user created by SMS has no password yet: set one with the SMS reset
curl $H -d '{"phoneNumber":"+15550001234"}' http://localhost:8080/api/auth/phone-number/request-password-reset
curl $H -d '{"phoneNumber":"+15550001234","otp":"654321","newPassword":"Password123!"}' \
  http://localhost:8080/api/auth/phone-number/reset-password

# 3. sign in with phone number + password
curl -c jar $H -d '{"phoneNumber":"+15550001234","password":"Password123!"}' http://localhost:8080/api/auth/sign-in/phone-number

# 4. an email/password user adds a number (signed in, jar holds the session)
curl -b jar $H -d '{"phoneNumber":"+15550005678"}' http://localhost:8080/api/auth/phone-number/send-otp
curl -b jar -c jar $H -d '{"phoneNumber":"+15550005678","code":"123456","updatePhoneNumber":true}' \
  http://localhost:8080/api/auth/phone-number/verify
```

## Errors

| Code | Status | When |
|---|---|---|
| `INVALID_PHONE_NUMBER` | 400 | `PhoneNumberValidator` rejected the number |
| `OTP_NOT_FOUND` | 400 | No code for the number (never sent, already used, or deleted after too many attempts) |
| `INVALID_OTP` | 400 | Wrong code. Each wrong guess counts as an attempt |
| `OTP_EXPIRED` | 400 | The code is older than `ExpiresIn` |
| `TOO_MANY_ATTEMPTS` | 403 | `AllowedAttempts` wrong guesses. The code is deleted |
| `INVALID_PHONE_NUMBER_OR_PASSWORD` | 401 | Sign-in with an unknown number, a wrong password, or a user without a password |
| `PHONE_NUMBER_NOT_VERIFIED` | 401 | Sign-in with `RequireVerification` and an unverified number. A new code was sent |
| `PHONE_NUMBER_EXIST` | 400 | `updatePhoneNumber` with a number that already belongs to a user |
| `USER_NOT_FOUND` | 401 | `updatePhoneNumber` without a session |
| `PHONE_NUMBER_CANNOT_BE_UPDATED` | 400 | `phoneNumber` sent to `/update-user` |
| `SEND_OTP_NOT_IMPLEMENTED` | 501 | `send-otp` without `SendOTP` |
| `PASSWORD_TOO_SHORT` / `PASSWORD_TOO_LONG` | 400 | `reset-password` outside `EmailAndPassword.Min/MaxPasswordLength` (8..128) |

## Notes

- Rate limits are enforced by goauth's global limiter while `AuthConfig.RateLimit` is enabled (default:
  production only). `/phone-number/*` allows 10 requests per 60s (the plugin's rule) and
  `/sign-in/phone-number` 3 per 10s (the `/sign-in` special rule), per client IP.
- With `updatePhoneNumber`, the code is used up before the session check, as in better-auth. A request
  without a session therefore burns the code.
- `EmailAndPassword.RevokeSessionsOnPasswordReset` and `OnPasswordReset` also apply to the SMS reset.
- To protect your own routes, see the "Protecting your own routes" section in
  [the username example](../username/example.md#protecting-your-own-routes).
