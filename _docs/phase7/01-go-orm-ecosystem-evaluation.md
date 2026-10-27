# 01: Go ORM & SQL Ecosystem Evaluation

## 1. Overview of the Go Data Access Landscape

Unlike Java (Hibernate) or Node.js (Prisma/TypeORM) where single frameworks dominate, the Go ecosystem is intentionally split into distinct paradigms. Go engineers tend to be pragmatic about database access, prioritizing performance, compile-time verification, and predictability over heavy ORM magic.

To make `better-go-auth` (`goauth`) universally adoptable, it must support the three primary data access paradigms in Go:
1. **Raw SQL with Compile-Time Codegen (`sqlc`)**: Write raw SQL, generate type-safe Go structs and query methods.
2. **Micro-ORMs / SQL-First Toolkits (`database/sql`, `sqlx`, `bun`)**: Keep SQL expressiveness while automating boilerplate row scanning or dynamic query building.
3. **Full-Featured Domain / Graph ORMs (`ent`, `gorm`)**: Define schemas in code, manage migrations, relations, and lifecycle hooks with high ergonomics.

---

## 2. Comprehensive Evaluation of Major Libraries

### 2.1. Standard Library: `database/sql`
* **Paradigm**: Low-level, driver-agnostic abstraction provided by the Go runtime.
* **Mechanism**: Relies on driver registration (`database/sql/driver`), connection pooling, and explicit `Rows.Scan(&col1, &col2...)`.
* **Strengths**:
  - Zero external dependencies. Guaranteed backward compatibility.
  - Ultimate control over queries, execution plans, and memory allocations.
  - Universal baseline: almost every other library builds on top of `*sql.DB` or `*sql.Tx`.
* **Weaknesses**:
  - High boilerplate: Every query requires manual column enumeration, pointer mapping, and `rows.Next()` / `rows.Scan()` loops.
  - High risk of typo errors or field order mismatches at runtime.
* **Fit for `goauth`**:
  - Essential as a baseline. Allows developers using custom architectures or zero-dependency frameworks to consume `goauth`.

---

### 2.2. `sqlx` (`github.com/jmoiron/sqlx`)
* **Paradigm**: Micro-wrapper enhancing `database/sql`.
* **Mechanism**: Adds struct scanning (`db.Get(&user, sql, id)`, `db.Select(&users, sql)`) via `db:"..."` struct tags, named query support (`NamedExec`), and dialect rebinding (`db.Rebind`).
* **Strengths**:
  - Retains 100% compatibility with standard `*sql.DB` and `*sql.Tx`.
  - Drastically reduces boilerplate over `database/sql` without hiding SQL queries.
  - Extremely stable, well-understood by enterprise Go engineers.
* **Weaknesses**:
  - Relies on runtime reflection to map column names to struct fields.
  - No built-in query builder or schema migration system.
  - Dialect handling for parameter placeholders (`$` for Postgres, `?` for MySQL/SQLite) must be explicitly managed via `db.Rebind()`.
* **Fit for `goauth`**:
  - High priority. A massive percentage of legacy and production Go applications use `sqlx`.

---

### 2.3. `sqlc` (`github.com/sqlc-dev/sqlc`)
* **Paradigm**: SQL-First, compile-time type-safe code generator.
* **Mechanism**: Parses raw DDL (`schema.sql`) and queries (`queries.sql`) using PostgreSQL / MySQL / SQLite AST parsers, and generates pure Go models, repository interfaces, and query execution methods.
* **Strengths**:
  - **Zero runtime reflection**: Execution is as fast and lean as handcrafted `database/sql`.
  - **Compile-time query verification**: Syntax errors, invalid table names, missing columns, or type mismatches fail during `sqlc generate`.
  - Fully transparent SQL: DBAs and developers see the exact queries executed.
* **Weaknesses**:
  - Dynamic queries (e.g., dynamic filtering and pagination with optional parameters) require pattern workarounds (e.g. `WHERE (@email::text IS NULL OR email = @email)`).
  - Code generation step required in build pipeline.
* **Fit for `goauth`**:
  - **Top tier recommendation**. `sqlc` is currently the fastest-growing data access tool in the modern Go community.

---

### 2.4. `Bun` (`github.com/uptrace/bun`)
* **Paradigm**: SQL-first, high-performance Go ORM (successor to `go-pg`).
* **Mechanism**: Provides a fluent query builder (`db.NewSelect().Model(&user)...`), struct mapping with `bun:"..."` tags, and dialect drivers for PostgreSQL, MySQL, and SQLite.
* **Strengths**:
  - Generates clear, predictable SQL without hidden N+1 queries.
  - Outstanding performance with custom byte-level struct scanners (drastically faster than GORM).
  - Built-in transaction management, table-name resolvers, soft delete, and migration engine (`bun/migrate`).
  - Already partially supported in `goauth` model struct tags (`bun:"..."`).
* **Weaknesses**:
  - Smaller ecosystem than GORM.
  - Dialect drivers require specific imports (`bun/dialect/pgdialect`, etc.).
* **Fit for `goauth`**:
  - **Immediate, natural fit**. `goauth` already has `bun:` tags on `User`, `Session`, and `OrganizationRole`. Creating a `bunauth` adapter is fast and yields great performance.

---

### 2.5. `Ent` (`entgo.io/ent`)
* **Paradigm**: Graph-based, code-generated ORM created by Meta / Ariga.
* **Mechanism**: Schemas are declared as Go code (`ent/schema/user.go`). Running `ent generate` creates 100% type-safe query builders, mutation clients, and schema validators.
* **Strengths**:
  - Unmatched type safety: Every field, edge (relationship), and predicate is generated as a typed function (e.g. `client.User.Query().Where(user.EmailEQ("alice@example.com")).Only(ctx)`).
  - Automatic migration and diff generation powered by Atlas.
  - Graph traversals (e.g. fetching user sessions, organization memberships, permissions) are elegant and verified at compile-time.
* **Weaknesses**:
  - Heavy code generation footprint (generates tens of thousands of lines of Go code).
  - Non-standard query syntax: Developers cannot easily copy/paste SQL queries.
  - Tight coupling to Ent's generated structs and client types.
* **Fit for `goauth`**:
  - High value for enterprise teams using Ent. Requires an adapter layer that converts between Ent-generated entities and `goauth` domain models.

---

### 2.6. `GORM` (`gorm.io/gorm`)
* **Paradigm**: Feature-rich Active Record / Data Mapper ORM.
* **Mechanism**: Uses runtime reflection, hooks (`BeforeSave`, `AfterCreate`), and associations to automatically inspect structs, construct SQL, and populate records.
* **Strengths**:
  - Very popular, fast to get started.
  - Built-in `AutoMigrate`, association handling, callbacks, and rich plugin ecosystem.
  - Already implemented as the initial database driver in `goauth`.
* **Weaknesses**:
  - Heavy reflection overhead, high heap allocations.
  - Silent runtime failures (e.g. mismatched tags or missing pointers do not fail at compile-time).
  - Leaks GORM types (`gorm.DeletedAt`, `gorm.DB`) into application domain structs if not strictly isolated.
* **Fit for `goauth`**:
  - Maintained as a first-class supported adapter, but decoupled from core models.

---

### 2.7. Notable Mentions: `pgx` & `Bob`
* **`pgx` (`github.com/jackc/pgx/v5`)**:
  - The gold-standard PostgreSQL driver and toolkit for Go.
  - Can be used via `database/sql` driver (`stdlib`) or natively with `pgxpool.Pool`.
  - For `goauth`, `database/sql`, `sqlx`, and `sqlc` all seamlessly run on top of `pgx/v5/stdlib`.
* **`Bob` (`github.com/stephenafamo/bob`) & `SQLBoiler`**:
  - Schema-first code generators. Good for existing complex enterprise databases. Lower market share than `sqlc` and `bun`.

---

## 3. Comparison Matrix

| Feature / Metric | `database/sql` | `sqlx` | `sqlc` | `Bun` | `Ent` | `GORM` |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Paradigm** | Raw Driver | Micro-ORM | SQL Codegen | SQL-First ORM | Graph Codegen | Active Record |
| **Type Safety** | None (Runtime) | Partial (Runtime) | **Compile-Time** | Partial (Runtime) | **Compile-Time** | None (Runtime) |
| **Reflection Cost** | Zero | Moderate | **Zero** | Low (Optimized) | **Zero** | High |
| **Query Transparency** | 100% (Manual) | 100% (Manual) | 100% (SQL) | High (Fluent) | Low (Graph DSL) | Low (ORM DSL) |
| **Dialect Portability** | Manual | Rebind | Native | Dialect Plugins | Drivers (Atlas) | Dialect Plugins |
| **Schema Migrations** | None | None | External | `bun/migrate` | Atlas Engine | `AutoMigrate` |
| **External Codegen** | No | No | Yes (`sqlc`) | No | Yes (`ent`) | No |
| **Effort to Implement in goauth** | Medium | Low | Medium | **Very Low** | High | Existing |
| **Adoption in Go Community** | Universal | Very High | High (Surging) | High | High (Enterprise) | Very High |

---

## 4. Architectural Recommendation for `goauth`

To maximize developer adoption without creating maintenance bloat, `goauth` should organize its data access into **3 tiers**:

### Tier 1: Core Adapters (Maintained in core repo)
1. **`gormauth`** (Existing, refactored to remove domain model leakage).
2. **`bunauth`** (Immediate win, models already tagged with `bun:`, high performance).
3. **`sqlcauth` / `stdsql`** (Compile-time verified raw SQL, zero reflection, supports standard `*sql.DB`, `sqlx`, and `pgx`).

### Tier 2: Ecosystem Adapters (Sub-packages or separate modules)
4. **`entauth`** (For teams committed to the Ent/Ariga graph ecosystem).
5. **`sqlxauth`** (Thin wrapper around raw SQL queries with `sqlx.DB`).

### Tier 3: Pluggable Interface (Universal)
Any developer can implement the 4 core repository interfaces (`IUserRepo`, `ISessionRepo`, `IOAuthAccountRepo`, `IVerificationRepo`) for any custom database or ORM in under 300 lines of Go code.
