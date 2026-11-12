# Phase 3 Roadmap & Task Queue

> **Document:** Phase 3 / Document 05  
> **Topic:** Prioritized Implementation Roadmap for Phase 3

---

## Priority 0: Fix Active Regressions & Unblock CI

- [x] **Remove `expires_at > now` pushdown from `gormauth/session_repo.go:ListSessions`**:
  * Restores contract suite passing in `src/app/repository/repotest`.
- [x] **Apply default `StoreSessionInDatabase = true` inside `sessionsvc.NewManager`**:
  * Restores test suite passing in `src/plugins/access-token/test`.
- [x] **Fix mutex race in `hooks.go:Register`**:
  * Removes unsynchronized slice allocation outside `h.mu.Lock()`.
- [x] **Align `RecordNotFound` error text to `"Not Found"` and decouple `errors.New`**:
  * Eliminates startup panic risks and aligns with standard Better Auth 404 text.
- [x] **Verification**: Ensure `go test ./...` passes 100% across all packages.

---

## Priority 1: Complete Organization Teams & Dynamic Roles

- [x] **Implement `ITeamService` in `src/plugins/org/services/serv.team.go`**:
  * Support team creation, updating, deletion, and membership management.
  * Enforce team limits: `MaximumTeams`, `MaximumMembersPerTeam`, `AllowRemovingAllTeams`.
- [x] **Mount Huma REST Endpoints for Teams**:
  * `POST /organization/team/create`
  * `POST /organization/team/update`
  * `POST /organization/team/delete`
  * `GET /organization/team/list`
  * `POST /organization/team/add-member`
  * `POST /organization/team/remove-member`
- [x] **Propagate `session.activeTeamId`**:
  * Wire `activeTeamId` into `CustomClaims` and the session resolver.
- [x] **Implement Dynamic Permission Evaluation**:
  * Parse and evaluate `OrganizationRole` permissions JSON document behind `OrgConfig.DynamicAccessControl.Enabled`.
- [x] **Tests**: Add end-to-end unit and integration tests in `src/plugins/org/test/`.

---

## Priority 2: Session Additional Fields & Custom ID Threading

- [x] **Thread Custom ID Generator**:
  * Pass `opts.Advanced.Database.GenerateID` through `InitContext` and constructor options into `gormauth` repositories for users, accounts, and verifications.
- [ ] **Generic `Session.AdditionalFields`** *(Deferred to Phase 4)*:
  * Allow users to declare custom session fields beyond the device allowlist, automatically migrating columns and exposing them through `/update-session` and `/get-session`.
- [ ] **Full `SessionPatch` Cutover** *(Deferred to Phase 4)*:
  * Deprecate `map[string]any` in `Manager.Update` and eliminate reflection in `setSessionFields`.

---

## Priority 3: Architecture & Multi-Tenancy Hardening

- [ ] **Eliminate Global State in `models/tables.go`** *(Partially Done - Instance NamingStrategy added, full removal deferred to Phase 4)*:
  * Replace global variables with GORM `schema.NamingStrategy` bound to each specific `*gorm.DB` instance to enable true multi-tenancy.
- [x] **Sanitize Origin Wildcard Compilation**:
  * Replace `regexp.MustCompile` with safe error-handled compilation in `src/providers/origin/origin.go`.
- [x] **Sanitize Production Logging**:
  * Update `logger.ErrorCtx` to check `term.IsTerminal` before emitting ANSI escape codes to stdout, preventing escape code pollution in JSON log forwarders.

---

## Priority 4: Ecosystem & Verification Against Official Upstream

- [x] **Automated CI Integration**:
  * Run the official `@better-auth/client` test script in GitHub Actions (`.github/workflows/ci.yml`) against Postgres and SQLite instances.
- [x] **Cross-Implementation Tests**:
  * Test cross-auth interoperability where a TypeScript Better Auth backend and GoAuth share the same database.
- [ ] **Clean Up Tech Debt** *(Deferred to Phase 4)*:
  * Delete dead, commented-out code blocks in `serv.session.go`, `access_token.plugin.go`, and `todo.md`.
