# Phase 4 Documentation Index

> **Document Version:** 1.0.0  
> **Date:** 2026-10-21  
> **Status:** Active Execution  
> **Target:** `better-go-auth/goauth`

---

## Overview

This directory contains the Phase 4 engineering tasks, security remediations, performance improvements, and architectural milestones for `goauth`.

| Document | Topic | Description |
| :--- | :--- | :--- |
| [**01. Phase 4 Tasks**](01-phase4-tasks.md) | Prioritized Task Queue | Full backlog spanning Security Vulnerabilities (VULN-01, 04, 05), Operational Bugs (BUG-01, 03, 04, 05, 06, 08), Session & Claims Performance, and Architecture Cleanup. |

---

## Key Priorities for Phase 4

1. **Security Vulnerability Remediation**:
   - Invalidate verification OTPs upon failed attempts / implement rate limiting (VULN-01).
   - Prevent account collision during email change verification (VULN-04).
   - Sign admin impersonation cookies with application secret (VULN-05).

2. **Operational Bug Fixes**:
   - Re-enable Bearer authorization header bypass in origin check (BUG-01).
   - Guard against slice panic on empty keys in `UpdateUser` (BUG-03).
   - Replace insecure random string generation fallback (BUG-04).
   - Support array audience and strict issuer validation in JWTs (BUG-05).
   - Fix 401 Unauthorized errors on email-otp change endpoints (BUG-06).
   - Ensure concurrency safety on active session cache index (BUG-08).

3. **Performance & Architecture**:
   - Eliminate redundant database queries (`FindUserByID`, `FindSessionByID`) in `ClaimsFromSession`.
   - Implement generic `Session.AdditionalFields` and complete cutover to `SessionPatch`.
   - Remove global table naming variables in favor of instance-scoped namers.
