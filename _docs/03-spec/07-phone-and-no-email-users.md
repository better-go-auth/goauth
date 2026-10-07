# 07 – Users without an email, and phone-only users

Status: design only, not implemented. Build after the huma adapter (plan step 6).

## Rule: `user.email` stays required and unique

better-auth's phone-number and anonymous plugins work this way: users without an email get a placeholder
address. A nullable email would break sharing the database with a TypeScript better-auth server, and every
lookup by email.

## Phone plugin (`src/plugins/phone`)

Built like the admin and org plugins, following better-auth's phone-number plugin
(`better-auth/packages/better-auth/src/plugins/phone-number`).

- **Columns:** the plugin's migration adds `user.phoneNumber` (unique, nullable) and `user.phoneNumberVerified`.
  The repo gets `FindUserByPhone`.
- **Sign-up by phone:** `POST /phone-number/verify` with an unknown number creates the user with
  - email from a `GetTempEmail(phone)` option, e.g. `15551234567@phone.myapp.invalid` (the `.invalid` domain never receives mail),
  - name from `GetTempName`,
  - `emailVerified=false`, `phoneNumberVerified=true`,

  then creates a session. Code-only sign-in needs no account row.
- **Codes** live in the `verification` table in better-auth's format:
  - sign-in code: identifier = phone number, value = `code:attempts`, capped by an allowed-attempts setting;
  - password reset: identifier = `<phone>-request-password-reset`.
  - better-auth stores codes in plain text; goauth's 6-digit codes are bcrypt-hashed. A shared database needs
    plain text, so this is a config switch.
- **Phone + password (optional):** `sign-in/phone-number` finds the user by phone, then checks the normal
  credential account. Phone password reset reuses the update-or-create logic in `ResetPassword`.
- **Sending SMS:** reuse `VerificationSender.SendVerificationCode(to, code)`.

## Changes needed in `src/app/services/auth`

- An `IsTempEmail` check (domain match or callback), so verification, reset and change-email messages are
  never sent to placeholder addresses.
- Phone users add a real email later through `ChangeEmail`; they are unverified, so the existing flows cover them.
- `phoneNumber` must never be settable through update-user, only through a verified code. It is already left
  out of the update-user allowlist.

## Users with neither email nor phone

Guests and anonymous users follow the same rule: a `temp-<id>@<domain>` placeholder (better-auth's anonymous
plugin), later linked to a real email or phone.
