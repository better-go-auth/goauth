# Phase 8: Custom Columns & Additional Fields Architecture Plan

## Executive Summary

In [Better Auth](https://better-auth.com), developers can dynamically declare **additional fields** on core entities (`user`, `session`, `organization`, etc.) directly via configuration:

```ts
export const auth = betterAuth({
    user: {
        additionalFields: {
            phoneNumber: { type: "string", required: false, input: true },
            loyaltyTier: { type: "string", defaultValue: "bronze", input: false }
        }
    }
})
```

These fields are automatically:
1. Validated during `signUpEmail` and `updateUser`.
2. Persisted into the database table (as real columns or structured metadata).
3. Returned in API responses (`/get-session`, `/sign-in/email`, `/user`).
4. Protected against unauthorized mass-assignment.

### The Go Challenge
In TypeScript, objects are open dynamic dictionaries (`Record<string, any>`). In **Go**, types are statically declared, structs are immutable at runtime, and data access layers are strictly typed. Furthermore, in Phase 7 we designed a multi-ORM abstraction supporting **GORM**, **Bun**, **`database/sql`**, **`sqlx`**, **`sqlc`**, and **`Ent`**.

This Phase 8 plan delivers a complete, production-grade architecture that provides **Better-Auth compatible `AdditionalFields` in Go** while maintaining compile-time type safety, zero mass-assignment vulnerabilities, and seamless compatibility across all Phase 7 ORMs.

---

## Documentation Suite

| Document | Description |
| :--- | :--- |
| **[01. Custom Fields Design Patterns in Go](file:///home/k/Documents/7proj/better-go-auth/goauth/_docs/phase8/01-custom-fields-design-patterns.md)** | Comparative evaluation of architectural patterns: Dynamic SQL Columns vs. JSONB Metadata vs. Generic Domain Entities (`User[T]`) vs. Struct Embedding. Trade-offs across type safety, performance, and SQL indexing. |
| **[02. Configuration & Validation Specification](file:///home/k/Documents/7proj/better-go-auth/goauth/_docs/phase8/02-configuration-and-validation-spec.md)** | The Go configuration schema for `AdditionalFields`, input validation engine, type coercion, mass-assignment guards (`input: false`), and Huma OpenAPI integration. |
| **[03. Multi-ORM Storage & Query Strategies](file:///home/k/Documents/7proj/better-go-auth/goauth/_docs/phase8/03-multi-orm-storage-strategies.md)** | Concrete implementation blueprints across GORM, Bun, standard `database/sql`, `sqlx`, `sqlc`, and Ent. Dynamic column selection, struct scanning, and repository method adaptations. |
| **[04. Dynamic Migrations & DDL Evolution](file:///home/k/Documents/7proj/better-go-auth/goauth/_docs/phase8/04-dynamic-migrations-and-ddl.md)** | Automated DDL generator and `IMigrator` extensions for dynamically adding custom columns across PostgreSQL, MySQL 8.0+, and SQLite with zero downtime. |
| **[05. Physical Columns Migration Engine](file:///home/k/Documents/7proj/better-go-auth/goauth/_docs/phase8/05-physical-columns-migration-engine.md)** | Deep-dive into physical column migrations: schema introspection, dialect DDL generation (`ALTER TABLE`), index creation, NOT NULL/default value handling, and edge cases across SQLite, Postgres, and MySQL. |
| **[06. Physical Columns Repository Architecture](file:///home/k/Documents/7proj/better-go-auth/goauth/_docs/phase8/06-physical-columns-repository-architecture.md)** | In-depth repository mechanics for physical columns across GORM, Bun, standard `database/sql`, `sqlx`, `sqlc`, and Ent: dynamic queries, row scanning into `CustomFields`, inserts, and partial updates. |
| **[07. Physical Columns Code Changes & Guide](file:///home/k/Documents/7proj/better-go-auth/goauth/_docs/phase8/07-physical-columns-code-changes-guide.md)** | File-by-file blueprint of exact additions and modifications across models, DTOs, migrations, repos, validation, and Huma HTTP routes. |

---

## Architectural Blueprint

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              HTTP & API Ingestion Layer                                │
│        POST /sign-up/email  |  POST /update-user  |  GET /get-session                  │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                          AdditionalFields Validation Engine                            │
│  - Checks `input: true` (prevents mass-assignment / privilege escalation)              │
│  - Type validation: string, number, boolean, date, json                                │
│  - Constraint checks: required, min/max, regex, custom validators                      │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ Sanitized Extra Fields: map[string]any
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                           Core Domain Entity Extension                                 │
│          models.User { Base; UserDto; CustomFields map[string]any }                    │
│                      (Or Generic User[T] for typed codebases)                          │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                     Multi-ORM Data Access Layer (Phase 7 Integrated)                   │
├───────────────────┬───────────────────┬───────────────────────┬────────────────────────┤
│   GORM Adapter    │    Bun Adapter    │   database/sql & sqlx │   sqlc & Ent Adapters  │
│  Dynamic Map/Cols │  Dynamic Column   │  Rebound SQL Query    │  JSON Metadata or      │
│  & Custom Scans   │  Expressions      │  Builder & StructScan │  Extensible DDL Schemas│
└───────────────────┴───────────────────┴───────────────────────┴────────────────────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│             Database Engines: PostgreSQL 14+  |  MySQL 8.0+  |  SQLite 3               │
│               Real Table Columns (ALTER TABLE)  OR  JSONB Metadata Column              │
└────────────────────────────────────────────────────────────────────────────────────────┘
```
