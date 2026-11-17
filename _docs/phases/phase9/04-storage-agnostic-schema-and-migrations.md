# 04 – Storage-agnostic schema: databases, ORMs and migration tools

[02-dynamic-columns-plan.md](02-dynamic-columns-plan.md) designs dynamic columns around GORM. This document
answers the next question: what changes when goauth has to support **more databases** (MongoDB, later
others), **more data-access styles** (Bun, `database/sql`/sqlx, pgx, sqlc, Ent) and **external migration
tools** (Atlas in both of its workflows, goose, golang-migrate)? It compares the options and recommends one
architecture. It replaces the per-ORM approach of `_docs/phases/phase8/03` and `06`, which implements dynamic
columns once per ORM.

---

## 1. Where goauth is GORM-bound today

| Place | Coupling | Problem for other backends |
|---|---|---|
| `SetupGoAuth` | `Conn *gorm.DB`; GORM `NamingStrategy` decides table/column names | names live in GORM, not in goauth |
| Core repos | `src/app/repository/gormauth` (hand-written) + `memory` | each new backend re-implements ~45 methods |
| Plugin repos | admin, org, jwt, passkey, two-factor take `InitContext.DB *gorm.DB` | a Mongo or Bun user can't install those plugins at all |
| Migrations | `IMigrator.Migrate(ctx)` = GORM `AutoMigrate` + hand-written fixes | no way to *generate* SQL, verify a schema, or hand migrations to Atlas |
| Queries | `gormutil.ILike`, `clause.Lt`, `LIKE … ESCAPE` | SQL-only building blocks |
| Dynamic columns (plan 02) | `Migrator().ColumnTypes`, `stmt.Schema.Fields` | would need a rewrite per backend |

Plan 02's registry is right, but if it's implemented as written, every new backend means writing the
dynamic-column logic again. Nothing has been built yet, so this is the time to make it storage-neutral.

---

## 2. How better-auth solves it (and why it matters)

better-auth supports Kysely (Postgres/MySQL/SQLite/MSSQL), Drizzle, Prisma, MongoDB and memory with the same
`additionalFields` feature. It does it with three layers:

1. **`getAuthTables(options)`**: one logical schema (models, fields, logical types, `references`, `unique`,
   `index`, `fieldName`/`modelName` overrides), merged from core, `additionalFields` and plugin `schema`.
2. **`createAdapter`**: a small generic CRUD interface (`create`, `findOne`, `findMany`, `count`, `update`,
   `updateMany`, `delete`, `deleteMany`, `transaction`) working on **plain records** with a portable `Where`
   (`eq, ne, lt, lte, gt, gte, in, not_in, contains, starts_with, ends_with`, `AND/OR`, case-insensitive
   mode). The shared factory handles field→column mapping, defaults, ID generation, date/JSON/boolean
   transforms; each backend only implements raw CRUD.
3. **The CLI** (`@better-auth/cli generate | migrate`): `migrate` applies additive DDL itself (Kysely only);
   `generate` writes the schema **in the format of the user's tool** (Prisma schema, Drizzle schema, SQL file).
   For MongoDB nothing is generated (schemaless).

Everything above the adapter (internalAdapter, every plugin) is written once. That is why a plugin like
two-factor works on Prisma and MongoDB without any adapter-specific code. goauth should copy this design.

---

## 3. Data-access options compared

| | A. Hand-written repos per backend (today, phase 8 docs) | B. Generic adapter + generic repos (better-auth model) | C. Code generation per app (sqlc/Ent style) | D. JSON blob for extras |
|---|---|---|---|---|
| Cost of a new backend | ~45 core methods + every plugin repo + dynamic columns | ~10 CRUD methods + a `Where` translator | a generator template per backend | same as A |
| Dynamic columns | implemented N times | implemented once (records are maps) | needs a regenerate + rebuild for each new field | trivial |
| Plugins on any backend | each plugin × each backend | automatic | generated | each plugin × each backend |
| Runtime `additionalFields` | yes | yes | no (compile time only) | yes |
| Type safety / speed | best | reflection map↔struct (~µs; negligible next to I/O) | best | good |
| Shared DB with a TS better-auth server | yes | yes | yes | **no** (TS reads real columns) |
| MongoDB | separate code | natural (documents are maps) | no mature Go generator | natural |
| Verdict | doesn't scale past 2 backends | **recommended** | only as an *output format* (see §5.3) | rejected for core; maybe opt-in later |

**Recommendation: B, with an escape hatch.** Repositories and plugins are written once against a generic
adapter. A backend may *additionally* implement a typed interface (for example `repo_interfaces.IUserRepo`)
for a hot path, and goauth uses it when present (`if r, ok := adapter.(repo_interfaces.IUserRepo)`). The
current hand-written GORM repos survive this way during the migration and can be removed later.

---

## 4. Target architecture

```
                core models + AuthConfig.*.AdditionalFields + Plugin.Schema()
                                       │
                                       ▼
                     src/schema  (Registry: logical, storage-neutral)
            model→table/collection, field→column, LogicalType, unique, index, references
                    │                         │                           │
          parse / output (plan 02)     src/adapter (generic CRUD)    src/schema/render (DDL & schema output)
                                           │                              │
           ┌────────────┬──────────┬───────┴─────┬──────────┐    ┌───────┼──────────┬───────────┬──────────┐
          gorm       sql (database/sql:   mongo        memory      SQL per   Atlas HCL  Ent schema  Prisma*  Mongo
         adapter     pgx, sqlx, Bun,      adapter      adapter     dialect   / external                     indexes
                     sqlc & Ent users)                                        schema
                                           │
                    generic repos (core IAuthRepos) + plugin repos, written once
```

### 4.1 Registry: logical, never SQL

`src/schema` must not import GORM or any driver. A field has a **logical type** (`string, number, integer,
boolean, date, json, string[], number[], id`), flags (`Required, Unique, Index, Sortable, Input, Returned`),
`References{Model, Field, OnDelete}`, a default, and a resolved storage name. Renderers and adapters turn
logical types into physical ones. The ID representation is a backend choice: string by default,
`ObjectId` on MongoDB, `serial` on SQL when `GenerateID = "serial"`.

The registry resolves names **once**: `ModelName`/`Fields` overrides, `TablePrefix`, and
`ColumnCase = snake|camel` (better-auth's default is camel). Adapters receive final names and never derive
them, so GORM's `NamingStrategy` becomes one consumer of the registry, not the source of truth.

### 4.2 The adapter contract (`src/adapter`)

```go
type Record = map[string]any // keys are registry field names, not columns

type Adapter interface {
	ID() string // "gorm", "sql", "mongo", "memory"
	Create(ctx context.Context, model string, data Record) (Record, error)
	FindOne(ctx context.Context, model string, where []Where, sel ...string) (Record, error)
	FindMany(ctx context.Context, model string, q Query) ([]Record, error) // where, sortBy, limit, offset, select
	Count(ctx context.Context, model string, where []Where) (int64, error)
	Update(ctx context.Context, model string, where []Where, data Record) (Record, error) // first match
	UpdateMany(ctx context.Context, model string, where []Where, data Record) (int64, error)
	Delete(ctx context.Context, model string, where []Where) error
	DeleteMany(ctx context.Context, model string, where []Where) (int64, error)
	Transaction(ctx context.Context, fn func(ctx context.Context) error) error
}

type Where struct {
	Field     string
	Op        Op   // Eq, Ne, Lt, Lte, Gt, Gte, In, NotIn, Contains, StartsWith, EndsWith
	Value     any
	Connector Conn // And (default) / Or
	Insensitive bool
}

// optional capabilities, discovered with type assertions
type Migrator interface{ Plan(ctx context.Context, reg *schema.Registry) (*schema.Plan, error); Apply(ctx context.Context, p *schema.Plan) error }
type Introspector interface{ Inspect(ctx context.Context) (*schema.Snapshot, error) }
type Joiner interface{ FindOneJoined(ctx context.Context, model string, where []Where, joins []Join) (Record, error) }
```

A shared `adapter.Factory` (like better-auth's `createAdapter`) wraps every backend and does the common
work: field→column renaming, defaults and `OnUpdate` values, ID generation, date normalisation (UTC,
millisecond precision), JSON encoding for SQLite, boolean coercion for MySQL `tinyint`, and turning
`Contains/StartsWith` into escaped patterns.

**The 9.1 fixes map onto this contract cleanly:**
- Compare-and-swap `UpdateVerificationValue` is `UpdateMany(where id=? AND value=?) == 1`. On MongoDB it is
  `updateOne(filter).ModifiedCount`.
- Atomic consume is `DeleteMany(where id=? AND value=?) == 1`.
- Expired cleanup is `DeleteMany(where expiresAt < now)`.

No backend needs special methods for them.

### 4.3 Generic repositories

`src/app/repository/adapterrepo` implements `IAuthRepos` once on top of `Adapter`: map ↔ `models.User`
(static fields by registry name, the rest into `Extra`), not-found mapping, soft-delete tombstones, uniqueness
errors normalised to `autherr`. `repotest` already defines the contract, so every adapter is validated by the
same suite: `repotest.Run(t, adapterrepo.New(gormAdapter))`, `…(sqlAdapter)`, `…(mongoAdapter)`.

Plugins stop receiving `*gorm.DB`: `InitContext.Adapter` replaces `InitContext.DB`, and plugin repos
(two-factor, passkey, jwt, org, admin) are rewritten once on the adapter. Keep `DB` for one release and mark it
deprecated.

### 4.4 Transactions shared with the application

This is the real reason to keep ORM-specific adapters. Apps want goauth's writes inside *their* transaction
("create organization + my billing row"). Each adapter therefore reads an ambient transaction from the
context in the same way:

- **gorm:** `gormutil.GetDB(ctx, db)` (exists today).
- **sql:** `sqladapter.WithTx(ctx, *sql.Tx)`. Bun's `bun.Tx`, sqlx's `*sqlx.Tx` and Ent's driver all expose
  the underlying `*sql.Tx`.
- **pgx:** `pgx.Tx` through a small interface.
- **mongo:** `mongo.SessionContext` (needs a replica set; without one, `Transaction` runs the function
  without atomicity and logs a warning once, which is better-auth's behaviour).

---

## 5. Backend by backend

### 5.1 SQL through `database/sql` (covers Bun, sqlx, pgx/stdlib, sqlc and Ent users)
One `sql` adapter with a dialect (`postgres`, `mysql`, `sqlite`, later `mssql`) and a small internal
query builder (or `squirrel`/`goqu`) is enough for all of these, because each of them can give goauth a
`*sql.DB`:

- **Bun:** `bunDB.DB`. Use the `sql` adapter. A dedicated Bun adapter is only worth it for `bun.Tx`
  ergonomics. The `bun:` struct tags already on the models are not needed by the generic path.
- **sqlx:** `sqlxDB.DB`.
- **pgx:** `stdlib.OpenDBFromPool(pool)`. A native pgx adapter can come later for `COPY`/performance.
- **sqlc:** sqlc generates code for *your* queries. goauth's tables are owned by goauth, so a sqlc app runs
  goauth on the `sql` adapter with the same `*sql.DB` and gets `goauth generate --format sql` output to put
  in its `schema/` folder. That way sqlc knows `user`/`session` for the app's own joins (§5.3). Generating a
  sqlc-based goauth repository is **not recommended**: runtime `additionalFields` can't exist in compiled
  queries, and every user would have to regenerate goauth's code.
- **Ent:** same approach. Run goauth on the `sql` adapter with Ent's `*sql.DB` (`entsql.OpenDB`).
  `goauth generate --format ent` writes Ent schema files (with `annotations.Skip` or views) so the app's graph
  can reference `User` and Ent's Atlas-based migration does not fight goauth over those tables.

### 5.2 GORM
It keeps its own adapter, because it is the current default, it shares the app's `*gorm.DB` and
transactions, and `AutoMigrate` works for static models. Internally it uses `db.Table(name)` with
`map[string]any`, so it never needs a Go struct for dynamic models. The current `gormauth` repos stay as the
typed escape hatch until the contract suite passes on the generic path.

### 5.3 MongoDB (and other document stores)
What changes compared to SQL:

| Concern | Decision |
|---|---|
| IDs | `_id` is an `ObjectId` by default (like better-auth's mongo adapter), exposed as `id` hex string; option `GenerateID` string IDs to share IDs with SQL-era data. Foreign keys (`userId`) stored as `ObjectId` when they reference an ObjectId model. |
| Field names | camelCase (registry `ColumnCase` is ignored, or forced to camel). |
| "Migrations" | no DDL. `Migrate` = create collections + indexes from the registry (`unique`, `index`, TTL index on `verification.expiresAt` and `session.expiresAt`, which removes the need for cleanup jobs). |
| Nullable unique fields | **Important**: a Mongo unique index treats missing/null as a value, so a second user without a phone number would conflict. Use `partialFilterExpression: {phoneNumber: {$type: "string"}}`. The registry has to mark *nullable unique* fields so the renderer can do this. |
| Case-insensitive email lookups | collation index (`strength: 2`) or store lower-cased email (better-auth lower-cases emails, so lower-cased storage is enough). |
| Joins (session + user, org members + user) | `$lookup`, or two queries in the factory (better-auth does the latter as the fallback). `Joiner` is optional. |
| Transactions | only on replica sets/sharded clusters (see §4.4). |
| `additionalFields` | free: documents take any field; validation happens in `ParseInput`. Optionally also emit a `$jsonSchema` validator. |

Other stores fit the same way: DynamoDB (single-table design needs `Query` access patterns, so it should
implement the typed escape-hatch interfaces), Redis-only (secondary storage already covers sessions),
CockroachDB/TiDB/MariaDB (SQL dialect variants), SQL Server (dialect + `OFFSET/FETCH`).

---

## 6. Migrations: the options, and Atlas

### 6.1 Who owns the schema?
Teams fall into three groups, and goauth should support all three:

1. **goauth owns it** (prototypes, small apps): migrate at startup, additive only. This is today's
   behaviour.
2. **A migration tool owns it** (goose, golang-migrate, Atlas versioned, Flyway): goauth must *produce*
   SQL files and never touch the database at startup. At most it *verifies* the schema.
3. **A declarative tool owns it** (Atlas declarative, Ent, Prisma, Drizzle): goauth must produce a
   *desired-state schema* in that tool's format. The tool diffs and applies it.

Config:

```go
GoAuth.Migrations.Mode = "auto"   // default: apply additive changes at startup (today)
                       | "verify" // inspect the DB at startup; fail fast listing the missing pieces and the SQL to fix them
                       | "off"    // trust the operator
```

`verify` is what makes groups 2 and 3 safe. It needs only the optional `Introspector` capability: Postgres
`information_schema`, MySQL `information_schema`, SQLite `pragma_table_info`, Mongo `listIndexes`.

### 6.2 Atlas supports several workflows; goauth should fit all of them without re-implementing Atlas

| Atlas workflow | What Atlas needs from goauth | goauth deliverable |
|---|---|---|
| **Declarative** (`atlas schema apply --to …`) | the desired state | `goauth schema --dialect postgres` prints full `CREATE TABLE/INDEX` SQL, or `--format hcl` prints Atlas HCL |
| **Versioned** (`atlas migrate diff` → files + `atlas.sum`, then `migrate apply`) | the same desired state; Atlas writes the versioned files | same command; Atlas does the diffing, renames, drops and lint |
| **External schema / ORM provider** (`data "external_schema"` in `atlas.hcl`, how `atlas-provider-gorm` works) | a program that prints the schema | `goauth schema` *is* that program. The app's `atlas.hcl` composes it with its own GORM/Ent schema: `data "composite_schema"` with goauth's tables + the app's tables |
| **Schema-as-code checks** (`atlas migrate lint`, drift detection in CI) | nothing extra | free once the above exists |

Example `atlas.hcl` for an app using GORM for its own models and goauth for auth:

```hcl
data "external_schema" "goauth" {
  program = ["go", "run", "./cmd/goauth-schema", "--dialect", "postgres"] // app-side main that calls goauth.Schema(cfg)
}
data "external_schema" "app" {
  program = ["go", "run", "ariga.io/atlas-provider-gorm", "load", "--path", "./models", "--dialect", "postgres"]
}
data "composite_schema" "all" {
  schema "public" { url = data.external_schema.goauth.url }
  schema "public" { url = data.external_schema.app.url }
}
env "local" {
  src = data.composite_schema.all.url
  dev = "docker://postgres/16/dev"
  migration { dir = "file://migrations" }
}
```

The program must live in the app because `additionalFields` and plugins are app configuration. goauth ships
`goauth.Schema(opts) (*schema.Registry, error)` plus `render.SQL(reg, dialect)` / `render.HCL(reg)`, so the
`main` is about five lines. The same entry point drives goose/golang-migrate users:
`goauth migrate generate --dir ./migrations` writes one timestamped **additive** SQL file (diff against a live
DB through the `Introspector`, like better-auth's `generate` for Kysely). Renames and drops stay
human/Atlas decisions.

**Decision: don't build a diff engine.** goauth's own migrator stays additive (add table/column/index,
never drop or alter). Anything smarter belongs to Atlas, which already does it well across dialects.

### 6.3 Render targets (`src/schema/render`)

| Target | Used by | Priority |
|---|---|---|
| `sql` per dialect (postgres, mysql, sqlite, mssql later) | auto/verify migrator, goose, golang-migrate, Atlas declarative/versioned, sqlc `schema/` | 1 |
| `atlas-hcl` | Atlas users who prefer HCL | 2 |
| `mongo` (collections, indexes, optional `$jsonSchema`) | Mongo migrator, ops scripts | 2 (with the Mongo adapter) |
| `ent` schema files | Ent apps referencing auth tables | 3 |
| `gorm` / `bun` model structs (`goauth generate --format go`) | apps that want typed access to auth tables in their own code | 3 |
| `prisma` / `drizzle` | shared database with a TypeScript better-auth server | 3; better-auth's CLI can already produce these from the TS config, so this only matters when Go is the source of truth |

All renderers read the same registry. That registry is therefore the only place where a column type is
decided per dialect (the type table in plan 02 §4.5 moves here).

---

## 7. What changes in plan 02

The ideas in plan 02 stay: registry, `ParseInput`, `Extra`, output flattening, compat decisions, tests. Its
storage parts become GORM-adapter details. Revised delivery order:

| # | Step | Notes |
|---|---|---|
| 1 | `src/schema` registry, **logical types only**, name resolution (`ModelName`, `Fields`, prefix, `ColumnCase`) | no GORM import, enforced with a `depguard`/import test |
| 2 | `ParseInput` + output (plan 02 steps 2–3) | unchanged |
| 3 | `src/adapter` contract + factory + `memory` adapter + `adapterrepo` generic `IAuthRepos`; run `repotest` on it | proves the contract before any SQL |
| 4 | `gorm` adapter (`db.Table` + maps); `repotest` on sqlite/postgres/mysql; `IAuthRepos` default switches to `adapterrepo(gorm)`, old `gormauth` kept as escape hatch | dynamic columns work here for the first time |
| 5 | `render.SQL` + additive migrator + `Migrations.Mode` (`auto`/`verify`/`off`) + `goauth schema` / `migrate generate` | Atlas declarative, versioned and external-schema all work from here |
| 6 | Plugins move to `InitContext.Adapter` (two-factor, passkey, jwt, org, admin) | `InitContext.DB` deprecated |
| 7 | `sql` adapter (`database/sql` + dialects) | unlocks Bun, sqlx, pgx, sqlc and Ent apps |
| 8 | `mongo` adapter + Mongo index renderer + partial unique indexes + TTL indexes | first non-SQL backend |
| 9 | `ColumnCase=camel`, shared-DB test with a TypeScript server; then `atlas-hcl`, `ent`, `go` renderers | |

Steps 1–3 are pure Go and can be reviewed without a database. Step 4 is the riskiest, because it changes the
default repository implementation. Run the full `repotest` + compat suites on all three SQL dialects before
switching the default.

---

## 8. Risks and how to contain them

| Risk | Mitigation |
|---|---|
| Generic `Where` can't express a query (`ListUsers` search, org member listing with user join) | add the op to the contract (better-auth's set has covered every plugin so far); the `Joiner` capability or the typed escape hatch for the rest |
| Reflection map↔struct cost on hot paths (`get-session`) | the session path is served from the cookie cache/secondary storage in most setups; benchmark in step 4 and add a typed fast path only where measured |
| Mongo vs SQL behavioural drift (null uniqueness, case folding, date precision) | the `repotest` contract gets cases for each of them; every adapter must pass the same suite |
| Atlas and goauth's auto-migrator both touching tables | `Migrations.Mode = "off"`/`"verify"` documented as required when Atlas (or any tool) owns the schema |
| Breaking plugin authors (`InitContext.DB`) | keep `DB` for one release, provide `pluginkit` helpers on the adapter so most plugins don't touch it directly |
| Existing snake_case GORM databases | `ColumnCase` defaults to `snake` for existing deployments; camel is opt-in (and the default only for new installs, decided when 9.2 ships) |
