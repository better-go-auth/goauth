# Database schema and migrations

goauth declares its database schema once, in the **schema registry** (`src/schema`): better-auth's core
tables, goauth's own columns, your `AdditionalFields`, `ModelName` / `Fields` renames, `GoAuth.ColumnCase`,
the id strategy, the `rateLimit` table and every plugin that declares tables. Everything else reads it: the
storage adapters (`src/adapter`: GORM, `database/sql`, MongoDB), the default repositories, the renderers
(`src/schema/render`: SQL, Atlas HCL, Ent, Go structs, Prisma, MongoDB indexes), goauth's own migrator and
the `goauth` CLI.

## Naming: snake or camel, renames

| Option | Effect |
|---|---|
| `GoAuth.ColumnCase = schema.Snake` (default) | `email_verified`, `user_id`, ... goauth's historical layout; existing databases keep working. |
| `GoAuth.ColumnCase = schema.Camel` | better-auth's layout (`emailVerified`, `userId`): share the database with a TypeScript better-auth server. Applies to the core tables and every plugin table (organization, two-factor, passkey, jwt, ...), which are all on the registry. |
| `User.ModelName = "users"` (also `Session`, `Account`, `Verification`, `RateLimit`) | renames the table (better-auth's `modelName`). |
| `User.Fields = {"emailVerified": "is_verified"}` | renames columns (better-auth's `fields`); used as is. |
| `GoAuth.TablePrefix`, `GoAuth.TableNames` | goauth's prefix / per-model table names (`ModelName` wins). |

Pass `SetupGoAuth` a `*gorm.DB` that hasn't used goauth's models yet: GORM caches parsed models per
connection, so models parsed under GORM's default naming would keep the old names (SetupGoAuth refuses such
a connection with an explanation).

`src/tests/compat/schemaparity` compares goauth's camel schema with the schema better-auth 1.6.16 creates
itself (core + every plugin goauth implements + `rateLimit`), both the database SetupGoAuth creates and
`goauth.GenerateSQL`. The remaining differences don't stop a TypeScript server sharing the database:
goauth-only extra columns (nullable or with defaults: the organization's `status`, `createdBy`, `orgType`,
`updatedAt` on the organization tables, the invitation's `acceptedById` / `acceptedAt`, the organization
role's `ops`, the jwks `alg` / `crv`), goauth's extra unique indexes on `account (providerId, accountId)` and
`organizationRole (organizationId, role)`, and no index on `twoFactor.secret` (goauth never queries by it,
and MySQL can't index the `text` column older goauth versions created).

**Databases created by goauth before the plugins moved onto the registry** (organization, two-factor,
passkey, jwt tables created with GORM `AutoMigrate`) keep working unchanged: the plugin tables have exactly
the registry's columns in both column cases (checked by `storagee2e.TestLegacyPluginTablesMatchRegistry`
on SQLite, Postgres and MySQL); `auto` only adds the two single-column indexes better-auth declares on
`organizationRole` (`organizationId`, `role`). Their organization tables still have the old NOT NULL
`updatedAt` (and `teamMember.createdAt`, `organizationRole.updatedAt`, `team.updatedAt`) columns, which a
TypeScript server doesn't fill; if a TypeScript server shares such a database, drop those NOT NULL
constraints (or give the columns a default) with your migration tool; goauth itself always writes them.

## Record ids

`Advanced.Database` maps better-auth's `generateId`:

| better-auth | goauth |
|---|---|
| (default) | `IDFormat: ""` / `config.IDFormatRandom`: 32-char `[a-zA-Z0-9]` |
| `generateId: "uuid"` | `IDFormat: config.IDFormatUUID` (stored as text) |
| `generateId: () => ...` | `GenerateID: func() string` |
| `generateId: false` | `IDFormat: config.IDFormatDatabase`: the database creates ids. Generated DDL gives `id` a default (`gen_random_uuid()::text` on Postgres, `(uuid())` on MySQL 8.0.13+, random hex on SQLite); replace it with your own if you like. |
| `generateId: "serial"` | `IDFormat: config.IDFormatSerial`: auto-increment integer ids; every column referencing an id (`session.userId`, ...) is an integer too. Go code and JSON still see strings (`"42"`). |

With `database` and `serial`, goauth creates records without an id and reads the database's id back
(`RETURNING` on Postgres and SQLite, `LAST_INSERT_ID()` on MySQL, else the row's unique values). Every goauth
plugin works with them (their tables are on the registry); third-party plugins that create GORM structs with
string ids of their own don't.

## Running without GORM: `database/sql` and MongoDB

`GoAuthOptions.Conn` (a `*gorm.DB`) is one way to give goauth a database. `GoAuthOptions.Adapter` is the
other: a storage backend that SetupGoAuth binds to the schema registry it builds. goauth then uses the
generic repositories on it, migrates through its `Migrator` (`Migrations.Mode` auto / verify / off work the
same), and hands it to plugins as `InitContext.Adapter`. `Conn` and `Adapter` are mutually exclusive.

| Backend | Package | Constructor |
|---|---|---|
| Postgres, MySQL, SQLite through any `database/sql` driver | `src/adapter/sqladapter` | `sqladapter.New(sqlDB, sqladapter.Postgres)` (an empty dialect is detected from the driver) |
| MongoDB (official driver v2) | `src/adapter/mongoadapter` | `mongoadapter.New(client.Database("app"))` |

```go
db, _ := sql.Open("pgx", os.Getenv("DATABASE_URL")) // or "mysql", "sqlite3", "sqlite", ...
auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	AuthConfig: cfg,
	Adapter:    sqladapter.New(db, sqladapter.Postgres),
})
```

Plugins that still keep GORM structs and need `InitContext.DB` (organization, admin, two-factor, passkey, jwt
until they move onto the registry) can't run this way yet: SetupGoAuth fails with a `*goauth.GORMRequiredError`
naming the plugin. Plugins that declare their tables with `SchemaProvider` (last-login-method, ...) work on
every adapter.

### The `database/sql` adapter

- **Dialects**: `postgres` (`$n` placeholders), `mysql`, `sqlite` (`?`). Identifiers are quoted per dialect;
  `contains` / `starts_with` / `ends_with` use escaped `LIKE … ESCAPE '!'` patterns (GLOB on SQLite and a
  binary comparison on MySQL when case-sensitive), case-insensitive conditions compare `LOWER(…)`.
- **Values**: Postgres and MySQL store dates and booleans natively; SQLite stores dates as ISO 8601 text with
  milliseconds (`2030-06-07T06:09:10.123Z`, better-auth's layout there) and booleans as `1` / `0`. JSON and
  arrays are JSON text (`jsonb` / `json` / `text` columns). MySQL works with or without `parseTime=true`.
- **Transactions**: `adapter.Transaction` opens a `*sql.Tx` and stores it in the context; calls made with
  that context join it. To put goauth's writes into **your** transaction, pass your `*sql.Tx` with
  `sqladapter.WithTx(ctx, tx)`: goauth never commits or rolls it back.
- **Ids**: `IDFormat` `database` / `serial` read the id back with `RETURNING` (Postgres, SQLite) or
  `LastInsertId` (MySQL auto-increment).
- **Unique violations** of pgx, lib/pq, go-sql-driver/mysql, mattn/go-sqlite3 and modernc.org/sqlite become
  `*adapter.UniqueError` (with the columns where the driver names them).
- **Migrations**: `Plan` / `Apply` (`adapter.Migrator`) and `Inspect` (`adapter.Introspector`) use
  `information_schema` / `pg_index` / `pragma_*` and the same additive DDL as the GORM backend
  (`src/schema/render`). `goauth.PlanMigration` / `GenerateMigration` and the CLI accept an `Adapter` too.

How each data-access style plugs in (they all end up handing goauth a `*sql.DB`):

**Bun** (`bun.DB` embeds `*sql.DB`; `bun.Tx` embeds `*sql.Tx`):

```go
sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
bunDB := bun.NewDB(sqldb, pgdialect.New())
opts.Adapter = sqladapter.New(bunDB.DB, sqladapter.Postgres)

// goauth's writes inside a Bun transaction
err := bunDB.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
	ctx = sqladapter.WithTx(ctx, tx.Tx)
	_, err := auth.Repositories().CreateUser(ctx, user) // or any goauth service call with ctx
	return err
})
```

**sqlx** (`sqlx.DB` embeds `*sql.DB`; `sqlx.Tx` embeds `*sql.Tx`):

```go
sqlxDB := sqlx.MustConnect("mysql", dsn)
opts.Adapter = sqladapter.New(sqlxDB.DB, sqladapter.MySQL)

tx := sqlxDB.MustBeginTx(ctx, nil)
ctx = sqladapter.WithTx(ctx, tx.Tx)
```

**pgx** (a `pgxpool.Pool` through pgx's `database/sql` bridge; a native pgx adapter can come later):

```go
pool, _ := pgxpool.New(ctx, dsn)
sqlDB := stdlib.OpenDBFromPool(pool)
opts.Adapter = sqladapter.New(sqlDB, sqladapter.Postgres)
```

**sqlc** (goauth owns its tables; sqlc only needs them in its `schema` folder for your own queries):

```go
sqlDB, _ := sql.Open("pgx", dsn)
queries := db.New(sqlDB) // sqlc-generated
opts.Adapter = sqladapter.New(sqlDB, sqladapter.Postgres)

tx, _ := sqlDB.BeginTx(ctx, nil)
qtx := queries.WithTx(tx)          // your queries
ctx = sqladapter.WithTx(ctx, tx)   // goauth's writes, same transaction
```

```sh
go run ./cmd/goauth-schema schema --dialect postgres > db/schema/goauth.sql   # sqlc's schema input
```

**Ent** (one `*sql.DB` for Ent's driver and goauth; `schema --format ent` writes Ent schemas for the auth
tables, marked `entsql.Skip()` so Ent's migration leaves them to goauth):

```go
sqlDB, _ := sql.Open("pgx", dsn)
client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, sqlDB)))
opts.Adapter = sqladapter.New(sqlDB, sqladapter.Postgres)
```

```sh
go run ./cmd/goauth-schema schema --format ent --out ./ent/schema   # User, Session, Account, ... schemas
```

### The MongoDB adapter

```go
client, _ := mongo.Connect(options.Client().ApplyURI(uri))
opts.Adapter = mongoadapter.New(client.Database("app")) // mongoadapter.WithStringIDs(), WithoutTTL()
```

- **Documents** are keyed by the registry's field names in camelCase whatever `ColumnCase` says (explicit
  `Fields` / `FieldName` renames are kept); one collection per model (`ModelName`, `TablePrefix` apply).
- **Ids** are ObjectIds in `_id`, exposed as 24-character hex strings; fields referencing an id
  (`session.userId`, ...) are stored as ObjectIds too. This is the default id generator unless
  `Advanced.Database.GenerateID` / `IDFormat` is set; ids that aren't ObjectId hex strings are stored as
  strings. `WithStringIDs()` stores every id as a string. `IDFormat: database` lets MongoDB create the
  ObjectId; `serial` is refused.
- **Queries**: `contains` / `starts_with` / `ends_with` are escaped `$regex`es, case-insensitive conditions
  use the `i` option; `ne` and `not_in` never match missing values (SQL's NULL semantics). `UpdateMany` /
  `DeleteMany` return matched / deleted counts, so the verification compare-and-swap and atomic consume work.
- **Transactions** use sessions on a replica set or sharded cluster. On a standalone server `Transaction`
  runs without atomicity and logs a warning once (better-auth's behaviour). An application session in the
  context (`mongo.NewSessionContext`) is joined.
- **"Migrations"** create the collections and the indexes: unique / index fields and multi-field indexes,
  **partial** unique indexes for optional unique fields (`partialFilterExpression: {phoneNumber: {$type:
  "string"}}`, so users without a phone number don't conflict), and TTL indexes on `verification.expiresAt` and
  `session.expiresAt` (MongoDB deletes expired rows itself). `verify` mode lists missing collections and
  indexes. `goauth schema --format mongo` prints them as JSON.
- Duplicate keys (E11000) become `*adapter.UniqueError` with the index's fields.

Tests: `go test ./src/adapter/sqladapter/... ./src/adapter/mongoadapter/... ./src/tests/compat/adaptere2e`
run the adapter contract (`adaptertest`), the repository contract (`repotest`) and a full server on SQLite;
set `TEST_POSTGRES_URL`, `TEST_MYSQL_URL`, `TEST_MONGO_URL` (standalone) and `TEST_MONGO_RS_URL` (replica
set, e.g. `mongodb://localhost:27017/?directConnection=true`) for the other backends.

## Migrations: who owns the schema

`GoAuth.Migrations.Mode`:

| Mode | What SetupGoAuth does | Use when |
|---|---|---|
| `auto` (default) | applies **additive** changes: missing tables, columns and indexes. Never drops, renames or alters. | goauth owns its tables (prototypes, small apps, today's behaviour). |
| `verify` | inspects the database and fails with every missing table/column/index and the SQL that creates it (`*goauth.SchemaMismatchError`). Changes nothing. | a migration tool owns the schema (Atlas, goose, golang-migrate, Flyway). |
| `off` | nothing. | you know what you are doing. |

What `auto` runs, in order:

1. **Core GORM bootstrap** (only with application-generated ids; `GoAuthOptions.Migrator` replaces it): the
   upgrades of databases created by older goauth versions (column renames and merges, obsolete indexes,
   MySQL binary collations for tokens and usernames, `name` backfill) and GORM `AutoMigrate` of the core
   structs, so the core column types of existing databases stay GORM's.
2. **Registry migrator** (`adapter.Migrator`, GORM backend): everything the registry declares that the
   database lacks: plugin `SchemaProvider` tables, the `rateLimit` table, `AdditionalFields` columns,
   indexes (matched by columns, not names), and with `database` / `serial` ids all core tables.
   Rules: a column is added `NOT NULL` only when it has a default the dialect accepts in `ADD COLUMN`;
   a required field **without** a default can only be added to an empty table, otherwise startup fails
   with `*gormadapter.RequiredColumnError` (give it a default, make it optional, or add and backfill the
   column yourself).
3. **Plugin migrators** (`Plugin.Migrator()`): only third-party plugins that still keep GORM structs (and
   custom organization / admin repositories passed with their own migrator). goauth's plugins return nil:
   their tables come from step 2.
4. The registry migrator once more (GORM's SQLite migrator rebuilds a table to add a foreign key and drops
   its indexes).

A second start is a no-op. `verify` and `off` skip all four steps; every goauth table, plugin tables
included, is part of `goauth.GenerateSQL` and the CLI output. Don't switch a database created from generated
SQL back to `auto` with a custom `Migrator` or GORM-struct plugins: GORM's AutoMigrate would adjust column
types and defaults to its struct tags.

## Generating SQL

Public API (root package):

```go
reg, err := goauth.Schema(opts)                               // the registry SetupGoAuth would build
sql, err := goauth.GenerateSQL(opts, render.Postgres)         // desired state: CREATE TABLE / CREATE INDEX
plan, dialect, err := goauth.PlanMigration(ctx, opts)         // what opts.Conn (or opts.Adapter) lacks
sql, err := goauth.GenerateMigration(ctx, opts)               // additive SQL for opts.Conn ("" = up to date)
```

`render.SQL(reg, dialect)` and `render.PlanSQL(plan, dialect)` do the rendering for Postgres, MySQL and
SQLite. Logical types become `text` / `varchar(255)` (MySQL indexed or unique, unique with `utf8mb4_bin`),
`double precision`, `bigint`, `boolean` (`integer` on SQLite), `timestamptz` / `datetime(3)` / `datetime`,
`jsonb` / `json` / `text`.

### The CLI

Because `AdditionalFields`, renames and plugins are app configuration, the schema program lives in your app:

```go
// cmd/goauth-schema/main.go
func main() {
	opts := myapp.AuthOptions() // the GoAuthOptions you pass to SetupGoAuth (Conn optional)
	if err := schemacli.Main(context.Background(), os.Args[1:], opts, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
```

```sh
go run ./cmd/goauth-schema schema --dialect postgres                     # desired state to stdout
go run ./cmd/goauth-schema migrate generate --dir ./migrations \
    --database-url "$DATABASE_URL" --format goose                         # one timestamped additive file
go run ./cmd/goauth-schema migrate status --database-url "$DATABASE_URL" # exit 1 when behind
```

Without app configuration, the stock binary takes the naming options as flags:

```sh
go run github.com/better-go-auth/goauth/src/cmd/goauth --column-case camel --id-format serial \
    --rate-limit-table schema --dialect mysql
```

### Other schema formats

`schema --format` renders the same registry for other tools (all from `src/schema/render`):

| `--format` | Output | Go API |
|---|---|---|
| `sql` (default) | desired-state DDL for `--dialect` | `render.SQL(reg, d)` |
| `hcl` | Atlas HCL schema for `--dialect` (`--schema`: the schema / MySQL database name; defaults `public`, `main`, `goauth`) | `render.HCL(reg, d)`, `render.HCLSchema(reg, d, name)` |
| `ent` | Ent schemas, one file per model (`--out dir`, `--package`); `entsql.Skip()` so Ent doesn't migrate goauth's tables | `render.Ent(reg, render.EntOptions{})` |
| `go` | Go structs for the auth tables, `--go-style gorm` (column / index / default tags, `TableName()`) or `plain` (`db` + `json` tags); GORM type tags with an explicit `--dialect` | `render.Go(reg, render.GoOptions{})` |
| `prisma` | `schema.prisma` like better-auth's Prisma generator (`--provider postgresql\|mysql\|sqlite\|mongodb`, default from `--dialect`) | `render.Prisma(reg, provider)` |
| `mongo` | MongoDB collections and indexes (partial unique, TTL) as JSON | `render.Mongo(reg)`, `render.MongoCollections` |

The golden files are checked against the real tools when they are available: `atlas schema inspect` / `schema
diff` (SQLite always; Postgres / MySQL with `ATLAS_DEV_POSTGRES_URL` / `ATLAS_DEV_MYSQL_URL`), an offline
`go build` of the Ent schemas, GORM's schema parser for the structs, and `prisma validate` (with
`GOAUTH_PRISMA_BIN` or `prisma` in `PATH`).

## Atlas

All three Atlas workflows read goauth's desired state; set `Migrations.Mode = verify` (or `off`) so goauth
never touches the tables Atlas manages.

**Declarative** (`atlas schema apply`):

```sh
go run ./cmd/goauth-schema schema --dialect postgres > goauth.sql
atlas schema apply --url "$DATABASE_URL" --to file://goauth.sql --dev-url "docker://postgres/16/dev"
```

**Versioned** (`atlas migrate diff` writes the files and `atlas.sum`, `atlas migrate apply` runs them) and
**external schema** (Atlas runs goauth's program, composed with your own GORM models):

```hcl
data "external_schema" "goauth" {
  program = ["go", "run", "./cmd/goauth-schema", "schema", "--dialect", "postgres"]
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

```sh
atlas migrate diff add_goauth --env local
atlas migrate apply --env local --url "$DATABASE_URL"
```

Renames and drops are Atlas decisions; goauth only ever adds.

## goose

```sh
go run ./cmd/goauth-schema migrate generate --dir ./migrations --format goose --database-url "$DATABASE_URL"
goose -dir ./migrations postgres "$DATABASE_URL" up
```

The file starts with `-- +goose Up`; add a `-- +goose Down` section if you want rollbacks.

## golang-migrate

```sh
go run ./cmd/goauth-schema migrate generate --dir ./migrations --format golang-migrate --database-url "$DATABASE_URL"
migrate -path ./migrations -database "$DATABASE_URL" up
```

Files are named `<timestamp>_goauth.up.sql`; write the matching `.down.sql` yourself if you need one.

## Plugin tables

A plugin declares its schema like better-auth's plugin `schema`:

1. Implement `plugins.SchemaProvider`: `Schema() schema.PluginSchema` returns fields for existing models
   (`"user": {Fields: ...}`) and new models (`"apiKey": {Fields: ..., Indexes: ...}`), with logical types,
   `Required`, `Unique`, `Index`, `References` and defaults. It is called before `Init`, so it may only
   depend on the plugin's options.
2. In `Init`, read and write the tables through `ictx.Adapter` with registry field names
   (`ictx.Adapter.Create(ctx, "apiKey", adapter.Record{...})`, `FindOne`, `UpdateMany`, ...); use
   `ictx.Schema` for table/column names and field definitions. `adapter.Transaction` joins the request's
   transaction (inside it, use the ctx passed to the function).
3. Return `nil` from `Migrator()`: the registry migrator creates the tables in `auto` mode, `verify` checks
   them, and `goauth.GenerateSQL` / the CLI include them. Names follow `ColumnCase`, ids follow the id
   strategy, and the plugin works with `database` / `serial` ids.

Fields a plugin adds to the core models exist only while the plugin is installed: admin (`role`, `banned`,
`banReason`, `banExpires`, `session.impersonatedBy`), phone-number, two-factor, username, anonymous and
organization (`session.activeOrganizationId`, `activeTeamId`, ...) declare theirs with `SchemaProvider`
(`schema.PluginFields(id)` returns better-auth's definitions). Without the plugin goauth neither creates
the columns nor reads or writes them (GORM skips the matching `models.User` / `models.Session` struct
fields); existing columns are never dropped, so a database keeps working when a plugin is removed and added
again. `GoAuthOptions.GORMRepositories` keeps every plugin column (its repositories store the Go structs).

## Additional fields

`User.AdditionalFields`, `Session.AdditionalFields`, `Account.AdditionalFields` and
`Verification.AdditionalFields` are better-auth's `additionalFields` (`schema.Field`: type, `Required`,
`Default` value or `func() any`, `Input`, `Returned`, `Validate`, `TransformIn`, enum values, ...). They are
real columns (created by the migrator) and work end to end:

| Where | Behaviour (better-auth's `parseInputData` / `parseUserOutput`) |
|---|---|
| `/sign-up/email`, `/sign-in/email-otp` (new user), `/phone-number/verify` (sign-up on verification) | the rest of the body is parsed for create: defaults (also for `input:false`), `MISSING_FIELD "<key> is required"`, `FIELD_NOT_ALLOWED "<key> is not allowed to be set"` for truthy `input:false` values, `VALIDATION_ERROR` for type, enum and validator errors; unknown keys are ignored |
| `/update-user`, `/update-session` | the same rules for update: no defaults, no required check; `User.GoAuth.RejectUnknownUpdateFields` rejects keys that are not user fields |
| `/admin/create-user` `data`, `/admin/update-user` `data` | spread into the user like better-auth (no input rules; values must fit their field, unknown keys ignored) |
| every response with a user or session (`/get-session`, sign-in/up, `/list-sessions`, admin users, plugin responses) | every returned field in schema order, `null` when unset, `returned:false` hidden |
| cookie cache (`session_data`, all strategies) and secondary storage | carry the fields in better-auth's JSON (a TypeScript server reads them, and goauth reads a TypeScript server's) |

In Go the values live in `models.User.Extra` (and `Session` / `Account` / `Verification`), or
`dtos.UserResponse.Extra` / `dtos.SessionData.Extra`: `schema.Get[string](user, "plan")`,
`user.SetExtra("plan", "pro")`.

## Database hooks and the internal adapter

`AuthConfig.DatabaseHooks` is better-auth's `databaseHooks`: `User` / `Session` / `Account` / `Verification`
× `Create` / `Update` / `Delete` × `Before` / `After` (package `dbhooks`). They run for every write, whoever
makes it (core endpoints, plugins, admin):

- `Create.Before(ctx, *T)` and `Delete.Before(ctx, *T)` see the record, `Update.Before(ctx, map)` the changes by
  field name (`dbhooks.Target(ctx)` is the updated row's id). A before hook changes the data in place,
  returns `dbhooks.ErrCancel` to cancel (better-auth's `return false`: sign-up answers 400
  `FAILED_TO_CREATE_USER`, sign-in 401 `FAILED_TO_CREATE_SESSION`, a cancelled update or delete is silent)
  or any other error (an `*autherr.AuthError` reaches the client as is).
- `After(ctx, *T)` sees the stored record; inside a transaction it runs once the transaction committed.
- Order: the `HookRegistry` typed hooks (`OnBeforeUserCreate`, `OnAfterUserCreate`), then plugin hooks
  (`plugins.DatabaseHooksProvider`, in plugin order), then `AuthConfig.DatabaseHooks`.
- goauth's bookkeeping writes (`lastLoginAt`, `lastLoginIP`, `session.lastUsedAt`) don't run update hooks.

Plugins write through `InitContext.Internal` (`GoAuth.Internal()`), goauth's `internalAdapter`:
`CreateUser`, `UpdateUser` (refreshes sessions cached in secondary storage), `DeleteUser` (sessions, plugin
rows, accounts, user), `CreateSession`, `UpdateSession`, `LinkAccount`, `UpdatePassword`, verification
helpers, `ParseUserInput` / `ParseSessionInput` and `SetUserFields`. Writes through `InitContext.IAuthRepos`
run the hooks too.

goauth's own plugins work this way (organization, two-factor, passkey, jwt; admin uses the core models):
their repositories map typed Go structs to records with `src/adapter/recordbind`, and the contract suite
`src/plugins/pluginrepotest` runs them on the memory adapter and on SQLite, Postgres and MySQL in both
column cases and with serial ids. `InitContext.DB` is deprecated and goes away in the next release.
