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

### TASK-401: Invalidate OTP on Failed Attempts (Fix VULN-01)
- [ ] **Problem**: In [`src/plugins/email-otp/services/email_otp_service.go`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/plugins/email-otp/services/email_otp_service.go), `VerifyEmail`, `SignIn`, and `ResetPassword` consume OTPs within `s.withTx(...)`. If password verification fails (`ErrInvalidOTP`), the transaction rolls back, restoring the consumed verification token. This enables unlimited brute-force attempts on 6-digit codes.
- [ ] **Implementation**:
  - Consume the verification token in a separate transaction or prior to password verification so failures cannot roll back the token consumption.
  - Implement an attempt counter on verification values, invalidating the code after a maximum threshold (e.g., 5 failed attempts).
  - Add rate limiting to `CheckVerificationOTP`.
- [ ] **Verification**: Add test cases submitting 5+ wrong OTPs and verifying that subsequent requests fail with `ErrInvalidOTP` or `ErrTooManyRequests` even within the validity window.

---

### TASK-402: Check Email Collision in `verifyEmailChange` (Fix VULN-04)
- [ ] **Problem**: In [`src/app/services/auth/core.verification.go:243-247`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/app/services/auth/core.verification.go#L243-L247), `verifyEmailChange` updates the user's email directly to `updateTo` without verifying whether `updateTo` was already registered by another account between token creation and redemption.
- [ ] **Implementation**:
  - Add `existing, err := s.repos.FindUserByEmail(ctx, updateTo)` before updating.
  - If a user exists with that email (and `existing.ID != user.ID`), return `autherr.ErrEmailAlreadyInUse`.
- [ ] **Verification**: Add test in `src/tests/auth` verifying that email change fails gracefully if target email is taken.

---

### TASK-403: Initialize Admin Impersonation Cookie Signing Secret (Fix VULN-05)
- [ ] **Problem**: In [`src/plugins/admin/admin.routes.go:16-21`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/plugins/admin/admin.routes.go#L16-L21), `handler.Cookies` is initialized with an empty `config.Config{}`, causing impersonation cookies to be signed with an empty secret string (`""`).
- [ ] **Implementation**:
  - Pass the root application secret and cookie options from `p.rootConfig` or `p.config` into `handler.Cfg` before constructing `cookies.New(handler.Cfg)`.
  - Alternatively, pass the shared `cookies.Manager` directly from the core application context.
- [ ] **Verification**: Add integration test verifying that admin impersonation cookies validate against standard session verification endpoints.

---

## 2. 🟠 Track 2: Operational Bug Fixes

### TASK-404: Re-enable Bearer Authorization Header Bypass in `originCheck` (Fix BUG-01)
- [ ] **Problem**: In [`src/app/adapters/huma/request.go:81-84`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/app/adapters/huma/request.go#L81-L84), the check bypassing origin validation for `Authorization: Bearer <token>` was commented out. Non-browser API clients (cURL, CLI, mobile apps) without an `Origin` header get rejected with `MISSING_OR_NULL_ORIGIN` if cookies are present.
- [ ] **Implementation**:
  - Uncomment and refine the Bearer header bypass in `originCheck`.
  - Ensure requests presenting a valid Bearer token bypass browser CSRF/Origin validation, adhering to Better Auth specification.
- [ ] **Verification**: Add test sending POST requests with `Authorization: Bearer ...` without `Origin` header.

---

### TASK-405: Guard Against Empty Key Panic in `UpdateUser` (Fix BUG-03)
- [ ] **Problem**: In [`src/app/adapters/huma/user_routes.go:131`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/app/adapters/huma/user_routes.go#L131), `upd.Fields[strings.ToUpper(k[:1])+k[1:]] = v` triggers a slice out-of-bounds runtime panic if JSON contains an empty key `""`.
- [ ] **Implementation**: Add `if len(k) == 0 { continue }` before title-casing the key.
- [ ] **Verification**: Add unit test passing empty key in `UpdateUser` JSON body.

---

### TASK-406: Make Cryptographic Randomness Fallback Safe (Fix BUG-04)
- [ ] **Problem**: In [`src/common/util/random-generator.go:16-19`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/common/util/random-generator.go#L16-L19), `GenerateRandomString` falls back to predictable characters `characters[i%len(characters)]` on `rand.Int` failure.
- [ ] **Implementation**: Eliminate fallback to predictable characters; panic with a descriptive message or propagate an error if system entropy fails.
- [ ] **Verification**: Review security guarantees and test with Mock reader error.

---

### TASK-407: Enforce Strict JWT Claim Verification (Fix BUG-05)
- [ ] **Problem**: In [`src/plugins/jwt/services/jwt_service.go:398-412`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/plugins/jwt/services/jwt_service.go#L398-L412), missing `iss` or `aud` claims silently skip validation because `ok` is false. Furthermore, array `aud` claims (`[]interface{}`) are not supported.
- [ ] **Implementation**:
  - When `expectedIss != ""`, require `iss` claim to be present and equal.
  - When `expectedAud != ""`, require `aud` claim to be present, and check for equality whether `aud` is string or `[]any` (per RFC 7519).
- [ ] **Verification**: Add tests validating JWTs with array audience and rejecting tokens missing required claims.

---

### TASK-408: Fix Email-OTP Email Change Endpoints (Fix BUG-06)
- [ ] **Problem**: Routes `/email-otp/request-email-change` and `/email-otp/change-email` require an authenticated session in `h.getSession(ctx)`, but lack `AuthHeaders` on their input structs and lack authentication middleware on route registration, resulting in perpetual 401 Unauthorized errors.
- [ ] **Implementation**:
  - Add `AuthHeaders humatypes.AuthHeaders` to `requestEmailChangeInput` and `changeEmailInput`.
  - Wire authentication middleware on these operations in [`src/plugins/email-otp/adapters/huma/routes.go`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/plugins/email-otp/adapters/huma/routes.go).
- [ ] **Verification**: Add end-to-end test in `src/plugins/email-otp/test` for email change flow.

---

### TASK-409: Concurrency-Safe Secondary Storage Active Sessions (Fix BUG-08)
- [ ] **Problem**: [`trackActive` and `untrackActive`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/app/services/session/manager-sec-store.go#L56-L109) perform non-atomic read-modify-write on `active-sessions-<userId>`. Concurrent logins can overwrite and drop active session tokens.
- [ ] **Implementation**:
  - For Redis storage, implement atomic sorted-set primitives (`ZADD`, `ZREM`, `ZREMRANGEBYSCORE`) or Redis Lua script.
  - For in-memory storage, ensure mutex locking over the entire read-modify-write lifecycle.
- [ ] **Verification**: Add parallel login concurrency test with `-race`.

---

## 3. ⚡ Track 3: Session Architecture & Performance

### TASK-410: Eliminate Redundant DB Queries in `ClaimsFromSession`
- [ ] **Problem**: In [`src/app/adapters/huma/session_claims.go:45-55`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/app/adapters/huma/session_claims.go#L45-L55), `ClaimsFromSession` executes `r.repos.FindUserByID` and `r.repos.FindSessionByID` on *every authenticated request* passing through middleware, negating session caching.
- [ ] **Implementation**:
  - Read `Role` from `sw.User.Role` and `ActiveOrgRole` from `sw.Session.ActiveOrganizationRole`, which are already populated in `sw *dtos.SessionWithUser`.
  - Only fall back to DB lookups if fields are missing or explicitly marked stale.
- [ ] **Verification**: Benchmark middleware performance and verify zero additional DB queries when session is cached.

---

### TASK-411: Generic `Session.AdditionalFields`
- [ ] **Problem**: Currently only a fixed allowlist of device fields (`DeviceToken`, `DeviceID`, etc.) is updatable. Better Auth allows users to declare arbitrary `additionalFields` on sessions.
- [ ] **Implementation**:
  - Add `AdditionalFields map[string]FieldDefinition` to `config.Session`.
  - Update migrator to create custom columns or JSON map on the session table.
  - Support reading and writing additional fields in `/update-session` and `/get-session`.
- [ ] **Verification**: Add contract tests declaring custom session fields and updating/retrieving them.

---

### TASK-412: Full `SessionPatch` Cutover
- [ ] **Problem**: [`Manager.UpdatePatch`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/app/services/session/manager.go#L485) converts `SessionPatch` to `map[string]any` via `patch.ToMap()` and relies on reflection and string matching in `setSessionFields`.
- [ ] **Implementation**:
  - Uncomment and wire `applyPatch(s *dtos.SessionData, patch config.SessionPatch)`.
  - Deprecate `map[string]any` updates in `Manager.Update` in favor of direct struct updates.
- [ ] **Verification**: Ensure all session tests pass without reflection overhead.

---

## 4. 🧹 Track 4: Architecture & Tech Debt

### TASK-413: Complete Removal of Package-Global Table State
- [ ] **Problem**: Package `models` retains global variables `tableMu`, `tablePrefix`, and `tableOverrides` in [`src/models/tables.go`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/models/tables.go). While `NamingStrategy` was introduced, models still call `models.TableName()` as a global fallback.
- [ ] **Implementation**:
  - Pass the GORM `schema.Namer` or context-scoped table resolver to all model queries.
  - Fully deprecate and remove `models.SetTableNames`.
- [ ] **Verification**: Add test configuring two concurrent `*gorm.DB` instances with distinct prefixes within the same test process.

---

### TASK-414: Clean Up Dead Code & Legacy Comments
- [ ] **Problem**: Dead commented-out code blocks remain in:
  - [`src/plugins/access-token/services/serv.session.go:165-245`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/plugins/access-token/services/serv.session.go#L165-L245)
  - [`src/plugins/access-token/access_token.plugin.go:49,199,474-476`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/plugins/access-token/access_token.plugin.go)
  - [`src/common/logger/logger.go:54-62`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/common/logger/logger.go#L54-L62)
- [ ] **Implementation**: Purge obsolete commented-out blocks, replacing with brief doc comments where appropriate.
- [ ] **Verification**: Run `golangci-lint` and `go test ./...`.
