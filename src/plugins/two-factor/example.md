# Two-factor plugin

Adds a second factor to password sign-in: a TOTP code from an authenticator app, a one-time code sent
by email or SMS, or a backup code. A browser can also be trusted for 30 days. It is the Go version of
better-auth's `twoFactor()` plugin and is compatible with the better-auth `twoFactorClient()` plugin.

Runnable example: [src/example/two-factor](../../example/two-factor/main.go)

```sh
go run ./src/example/two-factor     # server on http://localhost:8080, OpenAPI docs at /docs
go test ./src/example/two-factor    # the flow below, end to end
```

## Setup

```go
import (
	twofactor "github.com/better-go-auth/goauth/src/plugins/two-factor"
	tfconfig "github.com/better-go-auth/goauth/src/plugins/two-factor/config"
)

twoFactorPlugin := twofactor.New(tfconfig.Config{
	Issuer: "My App", // the name authenticator apps show (default: AppName)
	OTPOptions: tfconfig.OTPOptions{
		// optional: enables the email/SMS code method
		SendOTP: func(ctx context.Context, data tfconfig.SendOTPData, r *http.Request) error {
			return mailer.Send(data.User.Email, "Your code: "+data.OTP)
		},
	},
})

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: "http://localhost:8080", AppName: "My App"},
	Plugins:    []plugin.Plugin{twoFactorPlugin},
})
```

The plugin creates the `twoFactor` table (encrypted TOTP secret and backup codes) and adds the
`twoFactorEnabled` column to the user table. The migration runs during `SetupGoAuth`.

## Options

| Field | Default | Meaning |
|---|---|---|
| `Issuer` | `AppName` | Issuer in the TOTP URI returned by `/two-factor/enable` (`/get-totp-uri` always uses `AppName`, as in better-auth) |
| `SkipVerificationOnEnable` | false | Turn 2FA on in `/enable` instead of after the first `/verify-totp` |
| `AllowPasswordless` | false | Users without a password (social, passkey) can manage 2FA without one |
| `TrustDeviceMaxAge` | 30 days | How long `trustDevice` skips 2FA |
| `TwoFactorCookieMaxAge` | 10 min | How long a pending sign-in (the `two_factor` cookie) stays valid |
| `TOTPOptions.Digits` / `Period` / `Disable` | 6 / 30s / false | TOTP code settings. `Disable` turns the TOTP endpoints off |
| `OTPOptions.SendOTP` | nil | Sends the email/SMS code. Without it, `/send-otp` answers `OTP_NOT_CONFIGURED` |
| `OTPOptions.Digits` / `Period` / `AllowedAttempts` | 6 / 3 min / 5 | Email/SMS code settings |
| `OTPOptions.StoreOTP` | plain | `plain`, `hashed`, `encrypted` or custom callbacks |
| `BackupCodeOptions.Amount` / `Length` | 10 / 10 | Codes are shown as `xxxxx-xxxxx` |
| `BackupCodeOptions.StoreBackupCodes` | encrypted | `plain`, `encrypted` or custom `Encrypt`/`Decrypt` |
| `BackupCodeOptions.CustomBackupCodesGenerate` | nil | Replaces the code generator |

The functional options `twofactor.WithIssuer`, `WithSendOTP` and `WithRepo` set the same values.
On the server, `plugin.GenerateTOTP(secret)` and `plugin.ViewBackupCodes(ctx, userID)` match
better-auth's server-only `generateTOTP` and `viewBackupCodes`.

## Endpoints (under `/api/auth`, all POST)

| Path | Needs | Body | Response |
|---|---|---|---|
| `/two-factor/enable` | session | `password`, `issuer?` | `{ totpURI, backupCodes }` |
| `/two-factor/get-totp-uri` | session | `password` | `{ totpURI }` |
| `/two-factor/verify-totp` | session or `two_factor` cookie | `code`, `trustDevice?` | `{ token, user }` + session cookie |
| `/two-factor/send-otp` | session or `two_factor` cookie | `{}` | `{ status: true }` (code goes to `SendOTP`) |
| `/two-factor/verify-otp` | session or `two_factor` cookie | `code`, `trustDevice?` | `{ token, user }` + session cookie |
| `/two-factor/verify-backup-code` | session or `two_factor` cookie | `code`, `trustDevice?`, `disableSession?` | `{ token, user }` (`{ user }` with `disableSession`) |
| `/two-factor/generate-backup-codes` | session | `password` | `{ status, backupCodes }`. The old codes stop working |
| `/two-factor/disable` | fresh session | `password` | `{ status: true }` |

`password` is required unless `AllowPasswordless` is on and the user has no password. When
goauth's global limiter is enabled (`AuthConfig.RateLimit`, default: production only), each `/two-factor/*`
path allows 3 requests per 10 seconds (the plugin's rule).

When a user with 2FA on signs in through `/sign-in/email`, `/sign-in/username` or
`/sign-in/phone-number`, no session is created. The response is
`{ "twoFactorRedirect": true, "twoFactorMethods": ["totp", "otp"] }` and the signed `two_factor`
cookie identifies the pending sign-in. One of the verify endpoints then creates the session. The
methods list `totp` once a TOTP setup is verified and `otp` when `SendOTP` is set.

## Flow

```sh
H='-H Origin:http://localhost:8080 -H Content-Type:application/json'

# 1. sign up (or sign in), then enable 2FA: show totpURI as a QR code and keep the backup codes
curl -c jar -b jar $H -d '{"email":"alice@example.com","password":"Password123!","name":"Alice"}' \
  http://localhost:8080/api/auth/sign-up/email
curl -c jar -b jar $H -d '{"password":"Password123!"}' http://localhost:8080/api/auth/two-factor/enable

# 2. confirm with the first code from the app: twoFactorEnabled becomes true
curl -c jar -b jar $H -d '{"code":"123456"}' http://localhost:8080/api/auth/two-factor/verify-totp

# 3. a later sign-in answers {"twoFactorRedirect":true,...} and sets the two_factor cookie
curl -c jar2 $H -d '{"email":"alice@example.com","password":"Password123!"}' \
  http://localhost:8080/api/auth/sign-in/email

# 4. finish it with a TOTP code (or send-otp + verify-otp, or verify-backup-code)
curl -c jar2 -b jar2 $H -d '{"code":"654321","trustDevice":true}' \
  http://localhost:8080/api/auth/two-factor/verify-totp

# 5. the session cookie opens your protected routes
curl -b jar2 http://localhost:8080/api/example/me
```

With `"trustDevice": true` the response also sets a `trust_device` cookie. The next password sign-in
from that browser gets a session directly, and the cookie is rotated each time.

## Errors

| Code | Status | When |
|---|---|---|
| `INVALID_TWO_FACTOR_COOKIE` | 401 | No session and no valid, unexpired `two_factor` cookie |
| `INVALID_CODE` | 401 | Wrong TOTP or email/SMS code |
| `INVALID_BACKUP_CODE` | 401 | Unknown or already used backup code |
| `TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE` | 400 | `AllowedAttempts` wrong email/SMS codes. Request a new one |
| `OTP_HAS_EXPIRED` | 400 | The email/SMS code is older than `OTPOptions.Period` |
| `TOTP_NOT_ENABLED` | 400 | The user has no (verified) TOTP setup |
| `TWO_FACTOR_NOT_ENABLED` | 400 | `generate-backup-codes` before 2FA is on |
| `TOTP_NOT_CONFIGURED` / `OTP_NOT_CONFIGURED` | 400 | `TOTPOptions.Disable` is set / `SendOTP` is missing |
| `INVALID_PASSWORD` | 400 | Wrong `password` |
| `VALIDATION_ERROR` | 400 | `password` missing |
| `SESSION_NOT_FRESH` | 403 | `disable` with a session older than `Session.FreshAge` (default 1 day) |

## Notes

- 2FA turns on only after the first successful `/verify-totp` (or `/verify-otp`) while signed in,
  so a user who never scans the QR code is not locked out. `SkipVerificationOnEnable` changes that.
- `/verify-totp` and `/verify-otp` with a session replace the session cookie when they turn 2FA on.
- Sign-in with `rememberMe: false` is honoured: the session created after the second factor is a
  browser-session cookie.
- Deleting a user deletes their `twoFactor` row.
