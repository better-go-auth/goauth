# Phase 9: Hardening, dynamic columns and better-auth parity

Phase 9 started with the audit fixes and the five new plugins (two-factor, magic-link, phone-number, passkey,
social OAuth; see `_docs/tasks/task.md`). These documents plan what comes next.

| Document | Contents |
|---|---|
| [01 – Robustness and parity improvements](01-robustness-and-parity-improvements.md) | Concrete fixes to existing code (security, data integrity, error shapes), internal refactors that mirror better-auth's architecture (`internalAdapter`, `databaseHooks`, endpoint hooks, one rate limiter), operational and testing improvements. |
| [02 – Dynamic columns plan](02-dynamic-columns-plan.md) | How to implement better-auth's `additionalFields`, plugin `schema`, `fields` and `modelName` with real columns: schema registry, input/output parsing rules, migrations per dialect, repository changes, delivery steps and tests. |
| [04 – Storage-agnostic schema and migrations](04-storage-agnostic-schema-and-migrations.md) | How dynamic columns stay portable to MongoDB, Bun, `database/sql`/sqlx/pgx, sqlc, Ent and migration tools (Atlas declarative/versioned/external schema, goose, golang-migrate): option comparison, generic adapter contract, render targets, migration modes, revised delivery order for doc 02. |
| [03 – Missing features and compatibility gaps](03-missing-features-and-compat-gaps.md) | Blockers for full compatibility, missing core options, missing plugins with effort/value, behaviour differences in implemented plugins, and the suggested roadmap (phases 9.1–9.6). |

Top three priorities:
1. Data-integrity fixes: expired verification cleanup, atomic OTP attempt counters, admin delete releasing phone
   numbers, account uniqueness ([01](01-robustness-and-parity-improvements.md) §1).
2. Storage-neutral schema registry + generic adapter, then `additionalFields` + camelCase columns, which
   unblocks sharing a database with a TypeScript better-auth server and keeps MongoDB/Atlas/sqlc support
   possible ([02](02-dynamic-columns-plan.md), delivery order in [04](04-storage-agnostic-schema-and-migrations.md) §7).
3. Global rate limiter and the missing organization routes ([03](03-missing-features-and-compat-gaps.md) §1).
