didn't change any code. This is the same answer as before, now also checked against the session-feature list in your open doc, 3-comparison-and-verdict.md.

Current status
Area	State
Shared crypto, cookie and ID helpers	✅
Config	Partial. User and Account exist. Verification and RateLimit don't.
Tables (better-auth names)	✅ Still open: camelCase columns and the team / organizationRole tables.
Repositories and contract tests	✅
Session manager (sliding refresh, rememberMe, freshAge, secondary storage)	✅
Auth services in src/app/services/auth	✅ Built and tested, but nothing routes to them yet.
HTTP routes on top of the services, legacy JWT on the new core, admin/org alignment	Not started
Checked against section 3.3 of the doc:

Feature	In goauth?
Opaque tokens, sliding expiry, defer/disable refresh, rememberMe, freshAge	✅
Secondary-storage sessions and the active-sessions-<userId> list	✅
Session management API (list and revoke)	✅ in the services; only some is reachable over HTTP
Signed cookies, cookie prefix and secure-cookie settings	✅
update-session and extra session fields	❌
Cookie cache	❌ The option exists in config; get-session treats it as a no-op.
Origin/CSRF checks	❌ TrustedOrigins is configured but nothing checks it.
Impersonation	Partial. Missing: the admin_session cookie.
Bearer / JWT+JWKS plugins	❌ Bearer is only accepted today for the legacy JWT.
Hashed session tokens at rest (opt-in)	❌
What to add or change, in order
HTTP layer (step 6). Register the better-auth endpoints in src/app/adapters/huma on top of the new services.
Move core/ba there.
Map the results to cookies and redirects.
Merge the duplicate user/session response types.
Add golden tests.
Close the service gaps:
Atomic reset token: add a ConsumeVerificationValue repo method so a reset token can't be used twice.
Unlinking: add DeleteAccount(id) so unlinking removes one account instead of all accounts for that provider.
Missing endpoints: update-session, the delete-user email confirmation and its callback, and set-password.
Origin/CSRF check for cookie requests, using TrustedOrigins. This is a security gap, so it should come before the routes are public.
Ban check moves to the admin plugin. The session manager already stops session creation when the before-create hook returns an error, so the admin plugin can register the check there.
Legacy JWT on the new core (step 7), then aligning the admin and org plugins (steps 8–9).
Later:
cookie cache
bearer and JWT plugins
hashed tokens (opt-in)
rate limiting
camelCase columns
Users without an email, and phone-only users
Keep user.email required and unique. better-auth's phone-number and anonymous plugins work this way: users without an email get a placeholder address. A nullable email would break sharing the database with a TypeScript better-auth server, and every lookup by email.

Phone plugin (src/plugins/phone), built like the admin and org plugins and following better-auth's phone-number plugin:

Columns: the plugin's migration adds user.phoneNumber (unique, may be empty) and user.phoneNumberVerified. The repo gets FindUserByPhone.

Sign-up by phone: POST /phone-number/verify with an unknown number creates the user with:

email from a GetTempEmail(phone) option, for example 15551234567@phone.myapp.invalid; the .invalid domain can never receive mail;
emailVerified=false and phoneNumberVerified=true.
Then it creates a session. Code-only sign-in needs no account row.

Codes: stored in the verification table in better-auth's format.

Sign-in code: identifier = phone number, value = code:attempts, capped by an allowed-attempts setting.
Password reset: identifier = <phone>-request-password-reset.
better-auth stores codes in plain text, while goauth's 6-digit codes are bcrypt-hashed. Sharing a database with a TS server needs plain text, so this should be a config switch.
Phone + password (optional): sign-in/phone-number finds the user by phone, then checks the normal credential account. Phone password reset reuses the update-or-create logic in ResetPassword.

Sending SMS: reuse the existing VerificationSender.SendVerificationCode(to, code) interface.

Changes needed in the auth services:

Add an IsTempEmail check (domain match or callback). Verification, reset and change-email messages are then never sent to placeholder addresses.
Phone users add a real email later through ChangeEmail. They are unverified, so the existing flows already cover them.
phoneNumber must never be settable through update-user, only through a verified code. It's already left out of the allowlist; keep it that way.
Users with neither email nor phone (guests or anonymous users) follow the same rule. They get a temp-<id>@<domain> placeholder and are linked to a real email or phone later.

I'd build the HTTP layer first so the services are reachable, then the phone plugin on top of them.