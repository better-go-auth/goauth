# Phase 4 Tasks & Implementation Plan

> **Topic:** Prioritized Task Queue for Phase 4  
> **Source:** Phase 3 Deferred Tasks, Security Vulnerability Audit, and Performance Audits  
> **Target:** `better-go-auth/goauth`

---

## Executive Summary

Phase 3 successfully resolved the initial test regressions, implemented organization teams, team membership management, dynamic access control, custom ID generator threading, origin regex sanitization, and automated client CI compatibility tests.

Phase 4 focuses on:
1. **Security Vulnerability Remediation**: Eliminating the remaining open items from the security audit (OTP brute-force, email change collisions, impersonation cookie secret, and JWT claim verification).
2. **Operational Bug Fixes**: Fixing API client Bearer origin checks, empty key slicing panics, randomness fallbacks, and email-OTP change endpoints.
3. **Session Architecture & Performance**: Eliminating redundant DB hits in `ClaimsFromSession`, completing generic `Session.AdditionalFields`, and full cutover to typed `SessionPatch`.
4. **Multi-Tenancy & Tech Debt**: Fully removing global table state and purging commented-out code blocks.

---

## 1. 🔴 Track 1: Security Vulnerability Remediation

### TASK-401: Secure OTP Verification & Rate Limiting (Fix VULN-01)
- [x] **Status**: Resolved (See [Phase 4 Execution Report](03-phase4-execution-report.md#task-401-vuln-01-otp-verification--rate-limiting-architecture))
- [x] **Problem**: In [`src/plugins/email-otp/services/email_otp_service.go`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/plugins/email-otp/services/email_otp_service.go), `VerifyEmail`, `SignIn`, and `ResetPassword` consumed OTPs within `s.withTx(...)`. If password verification fails (`ErrInvalidOTP`), the transaction rolled back, restoring the consumed verification token. This enabled unthrottled brute-force attempts on 6-digit codes.
- [x] **Implementation**:
  - Verify OTP outside of the database transaction rollback block.
  - Verification tokens are consumed and deleted only upon successful verification or natural expiration, preventing third-party Account Lockout DoS attacks.
  - Rely on global route-level rate limiting (`Retry-After` / `429 Too Many Requests`) based on client IP per Better Auth specification.
- [x] **Verification**: Test cases verify that OTP codes verify cleanly and are consumed only upon success, while invalid codes are rejected without deleting the legitimate user's pending token.

---

### TASK-402: Check Email Collision in `verifyEmailChange` (Fix VULN-04)
- [x] **Status**: Resolved (See [Phase 4 Execution Report](03-phase4-execution-report.md#task-402-vuln-04-email-change-collision-check))
- [x] **Problem**: In [`src/app/services/auth/core.verification.go:243-247`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/app/services/auth/core.verification.go#L243-L247), `verifyEmailChange` updates the user's email directly to `updateTo` without verifying whether `updateTo` was already registered by another account between token creation and redemption.
- [x] **Implementation**:
  - Add `existing, err := s.repos.FindUserByEmail(ctx, updateTo)` before updating.
  - If a user exists with that email (and `existing.ID != user.ID`), return `autherr.ErrUserAlreadyExistsUseAnotherEmail`.
- [x] **Verification**: Added collision check returning `ErrUserAlreadyExistsUseAnotherEmail`.

---

### TASK-403: Initialize Admin Impersonation Cookie Signing Secret (Fix VULN-05)
- [x] **Status**: Resolved (See [Phase 4 Execution Report](03-phase4-execution-report.md#task-403-vuln-05-admin-impersonation-cookie-signing-secret))
- [x] **Problem**: In [`src/plugins/admin/admin.routes.go:16-21`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/plugins/admin/admin.routes.go#L16-L21), `handler.Cookies` is initialized with an empty `config.Config{}`, causing impersonation cookies to be signed with an empty secret string (`""`).
- [x] **Implementation**:
  - Pass the root application secret and cookie options from `p.rootConfig` or `p.config` into `handler.Cfg` before constructing `cookies.New(handler.Cfg)`.
- [x] **Verification**: Admin impersonation cookies validated with application secret in `src/tests/admin`.

---

## 2. 🟠 Track 2: Operational Bug Fixes

### TASK-404: Re-enable Bearer Authorization Header Bypass in `originCheck` (Fix BUG-01)
- [x] **Status**: Resolved (See [Phase 4 Execution Report](03-phase4-execution-report.md#task-404-bug-01-refined-bearer-header-origin-bypass))
- [x] **Problem**: In [`src/app/adapters/huma/request.go:81-84`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/app/adapters/huma/request.go#L81-L84), the check bypassing origin validation for `Authorization: Bearer <token>` was commented out. Non-browser API clients (cURL, CLI, mobile apps) without an `Origin` header get rejected with `MISSING_OR_NULL_ORIGIN` if cookies are present.
- [x] **Implementation**:
  - Uncomment and refine the Bearer header bypass in `originCheck` to allow requests without `Origin` headers while still enforcing origin restrictions when an `Origin` header is supplied.
- [x] **Verification**: Both non-browser requests and `TestBearerPlugin_UntrustedOriginBlocked` pass.

---

### TASK-405: Guard Against Empty Key Panic in `UpdateUser` (Fix BUG-03)
- [x] **Status**: Resolved (See [Phase 4 Execution Report](03-phase4-execution-report.md#task-405-bug-03-empty-key-panic-guard-in-updateuser))
- [x] **Problem**: In [`src/app/adapters/huma/user_routes.go:131`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/app/adapters/huma/user_routes.go#L131), `upd.Fields[strings.ToUpper(k[:1])+k[1:]] = v` triggers a slice out-of-bounds runtime panic if JSON contains an empty key `""`.
- [x] **Implementation**: Add `if len(k) == 0 { continue }` before title-casing the key.
- [x] **Verification**: Verified guard against empty keys.

---

### TASK-406: Make Cryptographic Randomness Fallback Safe (Fix BUG-04)
- [x] **Status**: Resolved (See [Phase 4 Execution Report](03-phase4-execution-report.md#task-406-bug-04-cryptographic-entropy-fallback))
- [x] **Problem**: In [`src/common/util/random-generator.go:16-19`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/common/util/random-generator.go#L16-L19), `GenerateRandomString` falls back to predictable characters `characters[i%len(characters)]` on `rand.Int` failure.
- [x] **Implementation**: Eliminate fallback to predictable characters; panic with a descriptive message if system entropy fails.
- [x] **Verification**: Cryptographic randomness fail-safe verified.

---

### TASK-407: Enforce Strict JWT Claim Verification (Fix BUG-05)
- [x] **Status**: Resolved (See [Phase 4 Execution Report](03-phase4-execution-report.md#task-407-bug-05-strict-jwt-claim--array-audience-verification))
- [x] **Problem**: In [`src/plugins/jwt/services/jwt_service.go:398-412`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/plugins/jwt/services/jwt_service.go#L398-L412), missing `iss` or `aud` claims silently skip validation because `ok` is false. Furthermore, array `aud` claims (`[]interface{}`) are not supported.
- [x] **Implementation**:
  - When `expectedIss != ""`, require `iss` claim to be present and equal.
  - When `expectedAud != ""`, require `aud` claim to be present, and check for equality whether `aud` is string or `[]any` (per RFC 7519).
- [x] **Verification**: Verified in `src/plugins/jwt/test`.

---

### TASK-408: Fix Email-OTP Email Change Endpoints (Fix BUG-06)
- [x] **Status**: Resolved (See [Phase 4 Execution Report](03-phase4-execution-report.md#task-408-bug-06-email-otp-email-change-endpoints))
- [x] **Problem**: Routes `/email-otp/request-email-change` and `/email-otp/change-email` require an authenticated session in `h.getSession(ctx)`, but lack `AuthHeaders` on their input structs and lack authentication middleware on route registration, resulting in perpetual 401 Unauthorized errors.
- [x] **Implementation**:
  - Add `AuthHeaders humatypes.AuthHeaders` to `requestEmailChangeInput` and `changeEmailInput`.
  - Wire authentication fallback resolution in handlers.
- [x] **Verification**: Verified in `src/plugins/email-otp/test`.

---

### TASK-409: Concurrency-Safe Secondary Storage Active Sessions (Fix BUG-08)
- [x] **Status**: Resolved (See [Phase 4 Execution Report](03-phase4-execution-report.md#task-409-bug-08-concurrency-safe-secondary-storage-active-sessions))
- [x] **Problem**: [`trackActive` and `untrackActive`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/app/services/session/manager-sec-store.go#L56-L109) perform non-atomic read-modify-write on `active-sessions-<userId>`. Concurrent logins can overwrite and drop active session tokens.
- [x] **Implementation**: Added `activeMu sync.Mutex` on `Manager` covering active sessions tracking and removal.
- [x] **Verification**: Concurrency-safe tracking verified under parallel tests.

---

## 3. ⚡ Track 3: Session Architecture & Performance

### TASK-410: Eliminate Redundant DB Queries in `ClaimsFromSession`
- [x] **Status**: Resolved (See [Phase 4 Execution Report](03-phase4-execution-report.md#task-410-eliminate-redundant-db-queries-in-claimsfromsession))
- [x] **Problem**: In [`src/app/adapters/huma/session_claims.go:45-55`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/app/adapters/huma/session_claims.go#L45-L55), `ClaimsFromSession` executes `r.repos.FindUserByID` and `r.repos.FindSessionByID` on *every authenticated request* passing through middleware, negating session caching.
- [x] **Implementation**:
  - Read `Role` from `sw.User.Role` and `ActiveOrgRole` from `sw.Session.ActiveOrganizationRole`, which are already populated in `sw *dtos.SessionWithUser`.
- [x] **Verification**: Verified zero additional DB lookups on cached sessions.

---

### TASK-411: Generic `Session.AdditionalFields`
- [ ] **Status**: 📋 Planned (See dedicated architecture plan in [02-session-additional-fields-plan.md](02-session-additional-fields-plan.md))
- [ ] **Problem**: Currently only a fixed allowlist of device fields (`DeviceToken`, `DeviceID`, etc.) is updatable. Better Auth allows users to declare arbitrary `additionalFields` on sessions.
- [ ] **Implementation**:
  - Add `AdditionalFields map[string]AdditionalFieldDefinition` to `config.SessionGoAuth`.
  - Update models to use JSON serialization on `Session.AdditionalFields`.
  - Wire validation and allowlist filtering in `/update-session` and `/get-session`.
- [ ] **Verification**: Unit and contract tests defined in the plan document.

---

### TASK-412: Full `SessionPatch` Cutover
- [x] **Status**: Resolved (See [Phase 4 Execution Report](03-phase4-execution-report.md#task-412-full-sessionpatch-cutover))
- [x] **Problem**: [`Manager.UpdatePatch`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/app/services/session/manager.go#L485) converted `SessionPatch` to `map[string]any` via `patch.ToMap()` and relied on reflection and string matching in `setSessionFields`.
- [x] **Implementation**:
  - Implemented typed `applyPatch` with zero reflection.
  - Corrected `UpdateSession` call in `UpdatePatch` to pass `sess.ID`.
- [x] **Verification**: All session and org team tests passing.

---

## 4. 🧹 Track 4: Architecture & Tech Debt

### TASK-413: Complete Removal of Package-Global Table State
- [x] **Status**: Resolved (See [Phase 4 Execution Report](03-phase4-execution-report.md#task-413-complete-removal-of-package-global-table-state))
- [x] **Problem**: Package `models` retained global variables `tableMu`, `tablePrefix`, and `tableOverrides` in [`src/models/tables.go`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/models/tables.go).
- [x] **Implementation**: Bound `NamingStrategy` to `opts.Conn` unconditionally in [`goauth.go`](file:///home/k/Documents/7proj/better-go-auth/goauth/goauth.go).
- [x] **Verification**: Verified instance isolation.

---

### TASK-414: Clean Up Dead Code & Legacy Comments
- [x] **Status**: Resolved (See [Phase 4 Execution Report](03-phase4-execution-report.md#task-414-clean-up-dead-code--legacy-comments))
- [x] **Problem**: Dead commented-out code blocks remained in access-token and logger packages.
- [x] **Implementation**: Purged dead commented blocks across `access-token` plugin and `logger.go`.
- [x] **Verification**: `go vet ./...` and `go test ./...` clean pass.
