# Architecture Strengths & Sound Design Decisions

> **Document:** Phase 3 / Document 02  
> **Topic:** Analysis of Core Strengths in `better-go-auth`

---

## 1. Wire & Protocol Compatibility

Better Auth client libraries expect exact route paths, HTTP status codes, cookie names, and JSON shapes. The framework:
* Exposes standard routes (`/sign-in/email`, `/sign-up/email`, `/sign-out`, `/get-session`, `/list-sessions`, `/revoke-session`).
* Ensures JSON responses match TypeScript shapes, using specialized serialization wrappers (such as `dtos.Time` for RFC3339 millisecond precision ISO strings).
* Emits errors strictly formatted as `{"code": "...", "message": "..."}`, allowing frontend Better Auth clients to map error codes seamlessly.

---

## 2. Unified Core Authentication Service

Earlier iterations suffered from split-brain logic between `authsvc.Service` and `plugins/access-token`:
* The `access-token` plugin originally reimplemented password hashing, credential lookup, user ban enforcement, and session creation.
* Unifying this flow so that `access-token` delegates authentication directly to `authsvc.Service.SignInEmail()` eliminated duplicate business logic and ensured lifecycle hooks (`OnBeforeUserCreate`, `OnUserBanned`) fire reliably across all login transports.

---

## 3. Defense-in-Depth Cryptography

The codebase prioritizes cryptographic security across all components:
* **Passwords**: Supports adaptive bcrypt, argon2, and scrypt implementations with automatic rehashing on successful authentication when password policies upgrade.
* **Random Sampling**: `idgen.RandomString` uses crypto rejection sampling, avoiding modulo bias on random token sequences.
* **Timing Attack Prevention**: Signed cookie parsing (`signedcookie.go`) and token comparisons use `crypto/subtle.ConstantTimeCompare`.
* **OTP Verification**: The `email-otp` plugin stores OTP codes as bcrypt hashes in the verification table, protecting in-flight OTPs even if the verification database is compromised.

---

## 4. Decoupled Repositories with Contract Verification

The data access layer cleanly separates interface from implementation:
* Services depend on abstract repository interfaces (`repo_interfaces.IAuthRepos`), not concrete `*gorm.DB` connections.
* Queries are written using struct conditions (`Where(&models.Session{Token: tok}, "Token")`), avoiding SQL string injection vulnerabilities and facilitating table renames.
* The test harness `src/app/repository/repotest` executes an identical suite of contract tests across SQLite GORM and in-memory repositories to prevent behavioral divergence.

---

## 5. Dual-Storage Cache-First Session Engine

The session manager (`sessionsvc.Manager`) is engineered for low latency:
* **Zero DB Hits**: Incoming authenticated requests check secondary storage (Redis or memory) first. If a session is found and valid, it is returned immediately without touching the relational database.
* **Graceful Degradation**: If secondary storage is down or unconfigured, the manager seamlessly falls back to the database.
* **Active Session Tracking**: User active sessions are indexed under `active-sessions-<userId>`, enabling atomic bulk revocation (`DeleteUserSessions`) and single-session enforcement (`SingleSession: true`).
