# 05 – Plugin parity plan (easy → hard)

Rules for every plugin:
- Folder `src/plugins/<better-auth-id>/` (e.g. `two-factor`, `email-otp`), `ID()` returns the
  better-auth id exactly.
- Implements Plugin v2 capabilities (03 §6.4): `Schema`, `Endpoints`, `Hooks`, `ErrorCodes`,
  `RateLimit` as needed.
- Endpoints, bodies, error codes copied from `better-auth/packages/better-auth/src/plugins/<id>/`
  (or `packages/<id>/` for separate packages). Port its `*.test.ts` cases into Go tests.
- Options struct mirrors the TS options (`camelCase` → `PascalCase`).

Effort: S ≤ 1 day · M 2–5 days · L 1–2 weeks · XL > 2 weeks.
Prereq column refers to roadmap phases.

## Tier 1 – small, no new tables (do first)

| # | Plugin | Endpoints | Schema changes | Effort | Prereq |
|---|---|---|---|---|---|
| 1 | **username** | `POST /sign-in/username`, `POST /is-username-available`; hooks on sign-up/update-user | user: `username` (unique), `displayUsername` | S | 4 |
| 2 | **anonymous** | `POST /sign-in/anonymous`, `POST /delete-anonymous-user`; `onLinkAccount` hook | user: `isAnonymous` | S | 4 |
| 3 | **last-login-method** | – (after hook sets `better-auth.last_used_login_method` cookie; optional DB field) | user: `lastLoginMethod` (opt.) | S | 6 |
| 4 | **bearer** | – (header in/out) | – | S | 3 |
| 5 | **multi-session** | `GET /multi-session/list-device-sessions`, `POST /multi-session/set-active`, `POST /multi-session/revoke` | – (multiple `{prefix}.session_token_multi-<n>` cookies) | M | 3 |
| 6 | **one-time-token** | `GET /one-time-token/generate`, `POST /one-time-token/verify` | uses verification | S | 4 |
| 7 | **custom-session** | – (wraps `get-session` response with user func) | – | S | 6 |
| 8 | **have-i-been-pwned** | – (before hook on sign-up/change/reset password; k-anonymity API) | – | S | 6 |
| 9 | **captcha** | – (before hook on configured paths; turnstile, reCAPTCHA, hCaptcha, captchafox) | – | S | 6 |

## Tier 2 – OTP / link based (reuse goauth's existing code flows)

| # | Plugin | Endpoints | Schema | Effort | Notes |
|---|---|---|---|---|---|
| 10 | **email-otp** | `POST /email-otp/send-verification-otp`, `/email-otp/check-verification-otp`, `/email-otp/verify-email`, `POST /sign-in/email-otp`, `/forget-password/email-otp`, `/email-otp/request-password-reset`, `/email-otp/reset-password`, `/email-otp/request-email-change`, `/email-otp/change-email` | verification | M | **Migrate goauth's `/verify`, `/forgot_password`, `/reset_password`, `/profile/verify_change_email` code flows here.** `otpLength=6`, `expiresIn=300s`, `allowedAttempts=3`, `storeOTP: plain\|hashed\|encrypted`, `overrideDefaultEmailVerification` |
| 11 | **magic-link** | `POST /sign-in/magic-link`, `GET /magic-link/verify` | verification | S | `expiresIn=300s`, `disableSignUp`, `storeToken` |
| 12 | **phone-number** | `POST /sign-in/phone-number`, `/phone-number/send-otp`, `/phone-number/verify`, `/phone-number/request-password-reset`, `/phone-number/reset-password` | user: `phoneNumber` (unique), `phoneNumberVerified` | M | `sendOTP` func, `signUpOnVerification`, `requireVerification` |
| 13 | **jwt** | `GET /token`, `GET /jwks` | `jwks` table | M | see roadmap 8.2 |

## Tier 3 – re-align existing goauth plugins

### 14. admin (M) – goauth has 12/15 endpoints

| better-auth | goauth today | Action |
|---|---|---|
| `GET /admin/list-users` (query) → `{users,total,limit?,offset?}` | `POST /admin/list-users` | change method & query params (`searchValue/searchField/searchOperator`, `limit`, `offset`, `sortBy`, `sortDirection`, `filterField/filterValue/filterOperator`) |
| `POST /admin/create-user {email,password,name,role?,data?}` → `{user}` | ✅ | align body/response |
| `POST /admin/set-role {userId, role}` → `{user}` | `/admin/set-user-role` | rename (keep alias in Legacy) |
| `POST /admin/set-user-password {userId,newPassword}` → `{status:true}` | ✅ | align |
| `POST /admin/remove-user {userId}` → `{success:true}` | ✅ | align |
| `POST /admin/ban-user {userId, banReason?, banExpiresIn?}` → `{user}` | ✅ | `banExpiresIn` is seconds; revoke sessions |
| `POST /admin/unban-user` | ✅ | align |
| `POST /admin/impersonate-user {userId}` → `{session,user}` | ✅ | set `session.impersonatedBy`, `admin_session` cookie, `impersonationSessionDuration=1h` |
| `POST /admin/stop-impersonating` | ✅ | restore from `admin_session` cookie |
| `POST /admin/list-user-sessions {userId}` → `{sessions}` | ✅ | align |
| `POST /admin/revoke-user-session {sessionToken}` / `revoke-user-sessions {userId}` | ✅ | align |
| `GET /admin/get-user?id=` | ❌ | add |
| `POST /admin/update-user {userId, data}` | ❌ | add |
| `POST /admin/has-permission {userId?, role?, permissions}` | ❌ | add (needs access control #16) |

Options: `defaultRole="user"`, `adminRoles=["admin"]`, `adminUserIds`, `defaultBanReason`,
`defaultBanExpiresIn`, `bannedUserMessage`, `impersonationSessionDuration`, `ac`, `roles`.
Ban check moves from core `Login` into an admin before-hook (`BANNED_USER` 403).

### 15. organization (L) – goauth has ~17/35 endpoints

Steps (each S–M):
1. Roles `owner`/`admin`/`member` (map `org_admin`→`admin` in migration); `creatorRole`.
2. `delete` → `POST {organizationId}`; all bodies use `organizationId` (optional = active org).
3. Move active org to `session.activeOrganizationId`; `set-active` updates session + cookie cache.
4. Add `check-slug`, `leave`, `get-active-member`, `get-active-member-role`,
   `list-user-invitations`, `has-permission`, server-only `addMember`.
5. Schema: `organization{id,name,slug,logo,metadata,createdAt}`, `member{id,organizationId,userId,role,createdAt}`,
   `invitation{id,organizationId,email,role,status,teamId?,inviterId,expiresAt,createdAt}`;
   goauth `status`, `createdBy`, `acceptedBy*` become `additionalFields`.
6. Teams (`teams.enabled`): `team`, `teamMember` tables; `create-team`, `list-teams`, `update-team`,
   `remove-team`, `set-active-team`, `list-user-teams`, `list-team-members`, `add-team-member`,
   `remove-team-member`; `session.activeTeamId`.
7. Dynamic access control (`dynamicAccessControl.enabled`): `organizationRole` table; `create-role`,
   `delete-role`, `list-roles`, `get-role`, `update-role` (replaces goauth `OrgPermission`).
8. Options: `allowUserToCreateOrganization`, `organizationLimit`, `membershipLimit`,
   `invitationExpiresIn=48h`, `sendInvitationEmail`, `cancelPendingInvitationsOnReInvite`,
   `requireEmailVerificationOnInvitation`, `organizationHooks` (before/after create/update/delete, members, invitations).
9. goauth extension: approval workflow (`approve/block/unblock`) behind `RequireApproval` option.

### 16. access (ac) (M)
`createAccessControl(statements)`, `role(...)`, `authorize(request)`; default statements for
admin (`user: [create,list,set-role,ban,impersonate,delete,set-password,get,update]`,
`session: [list,revoke,delete]`) and organization. Bridge goauth operation-ID RBAC onto it.

## Tier 4 – larger security plugins

| # | Plugin | Endpoints | Schema | Effort |
|---|---|---|---|---|
| 17 | **two-factor** | `/two-factor/enable`, `/disable`, `/get-totp-uri`, `/verify-totp`, `/send-otp`, `/verify-otp`, `/generate-backup-codes`, `/verify-backup-code` | user `twoFactorEnabled`; `twoFactor{id,secret(enc),backupCodes(enc),userId}` | L – TOTP RFC 6238 (`otpauth://` URI, 30 s, 6 digits), sign-in after-hook returns `{twoFactorRedirect:true}` and sets `two_factor` cookie, trusted-device cookie (30 d) |
| 18 | **api-key** (`packages/api-key`) | create, verify, get, update, delete, list, delete-all-expired | `apikey{id,name,start,prefix,key(hashed),userId,refillInterval,refillAmount,lastRefillAt,enabled,rateLimit*,requestCount,remaining,lastRequest,expiresAt,permissions,metadata,…}` | L – session from `x-api-key` header |
| 19 | **one-tap** | `POST /one-tap/callback` | – | S (after Google provider) |
| 20 | **generic-oauth** | `/sign-in/oauth2`, `/oauth2/callback/:providerId`, `/oauth2/link` | – | M (after Phase 9) |
| 21 | **device-authorization** | `/device/code`, `/device/token`, `/device`, `/device/approve`, `/device/deny` | `deviceCode` table | M (RFC 8628) |
| 22 | **siwe** | `/siwe/nonce`, `/siwe/verify` | `walletAddress` table | M |

## Tier 5 – heavy / protocol plugins

| # | Plugin | Effort | Notes |
|---|---|---|---|
| 23 | **passkey** (`packages/passkey`) | L | WebAuthn via `github.com/go-webauthn/webauthn`; table `passkey{id,name,publicKey,userId,credentialID,counter,deviceType,backedUp,transports,aaguid,createdAt}`; endpoints generate/verify register & authenticate options, list, delete, update |
| 24 | **oauth-provider** / **oidc-provider** / **mcp** | XL | authorization server: `/oauth2/authorize`, `/oauth2/token`, `/oauth2/userinfo`, `/oauth2/register`, consent, `.well-known/openid-configuration`; tables `oauthApplication`, `oauthAccessToken`, `oauthConsent`; depends on jwt plugin |
| 25 | **sso** (`packages/sso`) | XL | OIDC + SAML (`github.com/crewjam/saml`), domain verification, `ssoProvider` table, org provisioning |
| 26 | **scim** (`packages/scim`) | L | SCIM 2.0 Users/Groups, bearer SCIM token |
| 27 | **stripe** (`packages/stripe`) | L | `subscription` table, customer on sign-up, webhooks (`stripe-go`) |

## Social providers checklist (Phase 9)

`google, github, discord, microsoft, apple, gitlab, facebook, linkedin, twitter, twitch, spotify,
slack, reddit, notion, zoom, tiktok, dropbox, atlassian, cognito, figma, huggingface, kakao, kick,
line, linear, naver, paypal, polar, railway, roblox, salesforce, vercel, vk, wechat, paybin`
– implement first 5 natively; the rest can be thin configs over generic-oauth/OIDC discovery.

## Tracking table (update as work lands)

| Plugin | Status | PR | Compat tests |
|---|---|---|---|
| admin | 🟡 partial | | |
| organization | 🟡 partial | | |
| email-otp | ⬜ | | |
| username | ⬜ | | |
| anonymous | ⬜ | | |
| bearer | ⬜ | | |
| jwt | ⬜ | | |
| multi-session | ⬜ | | |
| magic-link | ⬜ | | |
| phone-number | ⬜ | | |
| two-factor | ⬜ | | |
| api-key | ⬜ | | |
| passkey | ⬜ | | |
| generic-oauth | ⬜ | | |
| oauth-provider | ⬜ | | |
| sso | ⬜ | | |
