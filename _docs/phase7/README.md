# Phase 7: Multi-ORM & Database Abstraction Architecture

## Overview & Executive Summary

The goal of Phase 7 is to transform `better-go-auth` (`goauth`) from a **GORM-centric** authentication library into a **database-agnostic, multi-ORM enterprise authentication engine**.

Modern Go backend ecosystems are diverse. While GORM is popular for rapid prototyping, many production engineering teams strictly prefer:
- **`sqlc`** for compile-time type safety without reflection or query builders.
- **Standard `database/sql`** for zero-dependency, high-throughput microservices.
- **`sqlx`** for struct scanning ergonomics while writing native SQL.
- **`Bun`** for high-performance, SQL-first query building with native bulk operations.
- **`Ent`** (Ariga/Facebook) for enterprise applications with complex domain graphs and code-generated type-safe APIs.

This documentation suite provides a complete, production-grade roadmap to make `goauth` fully compatible with all major Go ORMs and SQL toolkits.

---

## Documentation Structure

| Document | Description |
| :--- | :--- |
| **[01. Go ORM Ecosystem Evaluation](file:///home/k/Documents/7proj/better-go-auth/goauth/_docs/phase7/01-go-orm-ecosystem-evaluation.md)** | Deep comparative analysis of Go database libraries (`database/sql`, `sqlx`, `sqlc`, `bun`, `ent`, `gorm`, `pgx`, `bob`). Feature matrix, performance benchmarks, architectural trade-offs, and fitness for `goauth`. |
| **[02. Architecture Decoupling Strategy](file:///home/k/Documents/7proj/better-go-auth/goauth/_docs/phase7/02-architecture-decoupling-strategy.md)** | Core changes required to decouple `goauth` from GORM: Pure domain models vs. storage adapters, universal `ITransactionManager`, database error normalization, and repository contracts. |
| **[03. Implementation Plans by ORM](file:///home/k/Documents/7proj/better-go-auth/goauth/_docs/phase7/03-implementation-plans-by-orm.md)** | Step-by-step implementation blueprints for each adapter (`sqlc`, `database/sql`, `sqlx`, `bun`, `ent`, and refactoring `gorm`). File layouts, DDL, mapping logic, and code samples. |
| **[04. Schema Migrations & Testing Strategy](file:///home/k/Documents/7proj/better-go-auth/goauth/_docs/phase7/04-schema-migrations-and-testing-strategy.md)** | Unified schema migration management (embedded DDL vs. code-first), dialect handling (PostgreSQL, MySQL, SQLite), and test automation via `repotest.Run` and testcontainers. |

---

## Architectural Vision: Pluggable Repositories

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                      goauth Core Business Services & Handlers                    │
│   (AuthService, SessionService, OrganizationService, OAuthService, Middleware)   │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │ Calls domain methods
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                   Domain Repository & Transaction Interfaces                    │
│       (IUserRepo, ISessionRepo, IOAuthAccountRepo, IVerificationRepo, IOrgRepos)  │
│                           ITransactionManager, IMigrator                         │
└───────┬──────────────┬───────────────┬───────────────┬──────────────┬────────────┘
        │              │               │               │              │
        ▼              ▼               ▼               ▼              ▼
   ┌─────────┐    ┌─────────┐    ┌───────────┐    ┌─────────┐   ┌───────────┐
   │  GORM   │    │   Bun   │    │   sqlc    │    │  sqlx   │   │    Ent    │
   │ Adapter │    │ Adapter │    │  Adapter  │    │ Adapter │   │  Adapter  │
   └────┬────┘    └────┬────┘    └─────┬─────┘    └────┬────┘   └─────┬─────┘
        │              │               │               │              │
        ▼              ▼               ▼               ▼              ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │         Database Engines: SQLite 3  |  PostgreSQL 14+  |  MySQL 8.0+   │
   └────────────────────────────────────────────────────────────────────────┘
```

---

## Key Benefits of Multi-ORM Support
1. **Zero Lock-In**: Developers can integrate `goauth` into existing codebases without adopting a new ORM.
2. **Minimal Overhead**: High-performance services can use raw `database/sql` or `sqlc` to eliminate GORM reflection costs.
3. **Guaranteed Consistency**: Every adapter is validated against the exact same contract test suite (`repotest.Run`), guaranteeing 100% feature and behavioral parity across SQLite, PostgreSQL, and MySQL.
