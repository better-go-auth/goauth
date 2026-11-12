# Current State: What Is Done

> **Document:** Phase 3 / Document 01  
> **Source Plans:** `_docs/phase1/04-plan/02-steps.md`, `_docs/phase2/01-improvements-and-fixes.md`

---

## 1. Providers Layer (`src/providers/`)

* [x] **`authcrypto`**: Passwords hashed and verified via bcrypt, argon2, and scrypt with timing attack resistance. Token hashing (`TokenHash`, `TokenMatches`) with SHA-256. Verified against Better Auth test vectors.
* [x] **`cookies`**: Canonical `cookies.Manager` creating signed cookies (`signedcookie.go`) using HMAC-SHA256, following Better Auth cookie prefixing and security attributes (`SameSite`, `HttpOnly`, `Path`, `Domain`, `Secure`).
* [x] **`idgen`**: Default 32-character alphanumeric random token generator (`[a-zA-Z0-9]`) using rejection sampling to eliminate modulo bias. ULID generator retained for callers who construct IDs manually.
* [x] **`origin`**: Origin and CSRF validation supporting wildcard domains (`**`, `*`, `?`), protocol-relative path guards, and `$BETTER_AUTH_TRUSTED_ORIGINS` environment variables.
* [x] **`sec-storage`**: Pluggable secondary storage interfaces supporting in-memory (`memory.Store`) and Redis backends with key-level TTLs.

---

## 2. Models & Migrations (`src/models/`)

* [x] **Core Models**: `User`, `Session`, `Account`, `Verification` aligned with Better Auth wire fields and snake_case DDL table naming.
* [x] **Table Name Customization**: Dynamic table prefixes and per-model table name overrides via `models.SetTableNames()`.
* [x] **GORM Migrator**: Core migrations (`core_migration.GORMMigrator`) handling column preparation (`active_org_id` $\to$ `active_organization_id`), MySQL binary collation on session tokens (`utf8mb4_bin`), and MySQL `id` column widening to 32 characters.
* [x] **Timestamps & Serialization**: UTC normalization before persistence (`BeforeSave` hooks) and `models/dtos/better_auth.go` (`dtos.Time`) ensuring RFC3339 millisecond precision JSON output matching the TypeScript server.

---

## 3. Repositories (`src/app/repository/`)

* [x] **Struct-Condition Queries**: `gormauth` repositories for users, sessions, accounts, and verifications query by struct field matching (`Where(&models.Session{Token: tok}, "Token")`), eliminating raw SQL column strings and injection risks.
* [x] **Transactions**: Context-aware transaction manager (`gormutil.GormTxManager`) supporting nested-safe transaction propagation via `ctx.Value(gormutil.TxKey)`.
* [x] **Contract Suite**: `src/app/repository/repotest` executes an identical test suite against both GORM SQLite and in-memory repository implementations.

---

## 4. Unified Auth Services (`src/app/services/auth/`)

* [x] **Core Endpoints Handled**: Sign-up with email/password, sign-in with credentials, sign-out, session retrieval, session list, session revocation, change email, change password, reset password flow, delete user flow, and account unlinking.
* [x] **Hooks & Senders**: Pluggable callback hooks (`SendVerificationEmail`, `SendResetPassword`, `SendDeleteAccountVerification`, `OnPasswordReset`).
* [x] **User Status Management**: Admin ban checks enforced via `autherr.ErrBannedUser` during session creation.

---

## 5. Session Management (`src/app/services/session/`)

* [x] **Dual Storage Engine**: Simultaneous secondary storage caching and database persistence with zero-DB-hit lookups when cached in Redis/memory.
* [x] **Active Session Indexing**: User active sessions indexed under `active-sessions-<userId>` with automatic eviction upon logout or expiry.
* [x] **Sliding Expiration & Freshness**: Better Auth rules for session extension (`UpdateAge`) and recent re-authentication verification (`FreshAge`).

---

## 6. HTTP Adapters & Huma Routes (`src/app/adapters/huma/`)

* [x] **Better Auth REST Compliance**: Routes mounted matching Better Auth specifications: `/sign-up/email`, `/sign-in/email`, `/sign-out`, `/get-session`, `/list-sessions`, `/revoke-session`, `/change-password`, `/reset-password`, etc.
* [x] **Wire Error Format**: Standard `{"code": "...", "message": "..."}` response payloads using `types.WrapAPI(api)` and scoped error interceptors.
* [x] **Golden Test Suite**: `src/tests/compat/endpoints_test.go` verifying response structures against golden fixtures.

---

## 7. Plugins Layer (`src/plugins/`)

* [x] **`admin`**: User pagination (`/admin/list-users`), role assignment (`/admin/set-role`), user ban/unban, and session impersonation (`impersonatedBy`).
* [x] **`bearer`**: Authorization header (`Bearer <token>`) parsing and translation to signed session cookies for transparent middleware interop.
* [x] **`jwt`**: JWKS endpoint (`/.well-known/jwks.json`) and asymmetric JWT issuance.
* [x] **`email-otp`**: Numeric OTP code generation, bcrypt hashing, and verification.
* [x] **`org`**: Organization creation, membership, role hierarchy (`owner`, `admin`, `member`), invitations, and active organization switching.
* [x] **`access-token`**: Legacy dual-token issuance (JWT access token + session refresh token) unified over `authsvc.Service`.

---

## 8. Phase 2 Polish Landed (`feat/improvements-1-10`)

* [x] **Typed `InitContext`**: Removed `Extras map[string]any`; plugins now receive explicitly typed dependencies (`DB`, `CookieManager`, `SessionManager`, `SecondaryStorage`, etc.).
* [x] **Session Revocation Key Parity**: Core revocation standardized to `sec_storage.RevokedSessionPrefix` (`"revoked:session:"`), with plugin-owned index `SidPrefix` (`"sid:"`).
* [x] **`GoAuth` Encapsulation**: Private struct fields exposed via read-only getter methods (`Options()`, `Sessions()`, `Cookies()`, etc.) and generic `GetPlugin[T]()`.
* [x] **Safe Cookie Injection**: Cookie injection in `access-token` and `bearer` plugins uses `injectCookieHeader` / `bearerCookieValue` with `idgen.IsToken()` validation.
