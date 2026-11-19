# Database schema and migrations

goauth declares its database schema once, in the **schema registry** (`src/schema`): better-auth's core
tables, goauth's own columns, your `AdditionalFields`, `ModelName` / `Fields` renames, `GoAuth.ColumnCase`,
the id strategy, the `rateLimit` table and every plugin that declares tables. Everything else reads it: the
storage adapter (`src/adapter`), the default repositories, the SQL renderer (`src/schema/render`), goauth's
own migrator and the `goauth` CLI.

## Naming: snake or camel, renames

| Option | Effect |
|---|---|
| `GoAuth.ColumnCase = schema.Snake` (default) | `email_verified`, `user_id`, ... goauth's historical layout; existing databases keep working. |
| `GoAuth.ColumnCase = schema.Camel` | better-auth's layout (`emailVerified`, `userId`): share the database with a TypeScript better-auth server. Applies to the core tables, the adapter **and** the GORM-based plugin tables (organization, two-factor, passkey, jwt) through the GORM naming strategy. |
| `User.ModelName = "users"` (also `Session`, `Account`, `Verification`, `RateLimit`) | renames the table (better-auth's `modelName`). |
| `User.Fields = {"emailVerified": "is_verified"}` | renames columns (better-auth's `fields`); used as is. |
| `GoAuth.TablePrefix`, `GoAuth.TableNames` | goauth's prefix / per-model table names (`ModelName` wins). |

Pass `SetupGoAuth` a `*gorm.DB` that hasn't used goauth's models yet: GORM caches parsed models per
connection, so models parsed under GORM's default naming would keep the old names (SetupGoAuth refuses such
a connection with an explanation).

`src/tests/compat/schemaparity` compares goauth's camel schema with the schema better-auth 1.6.16 creates
itself (core + every plugin goauth implements + `rateLimit`). The remaining differences are goauth-only
extra columns (nullable or with defaults), goauth's extra unique index on `account (providerId, accountId)`,
missing foreign keys on some GORM plugin tables, and NOT NULL `createdAt`/`updatedAt` columns on the
organization tables, which a TypeScript server sharing the database would fail to insert into until the
organization plugin moves its tables onto the registry (missing-tasks 2.9).

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
(`RETURNING` on Postgres and SQLite, `LAST_INSERT_ID()` on MySQL, else the row's unique values). Plugins
that still store GORM structs with goauth-generated string ids (organization, two-factor, passkey, jwt,
admin) can't be combined with them yet; SetupGoAuth says so.

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
   structs. It stays because the GORM-based organization and admin plugins migrate those structs through
   their relations, so the core column types stay GORM's.
2. **Registry migrator** (`adapter.Migrator`, GORM backend): everything the registry declares that the
   database lacks: plugin `SchemaProvider` tables, the `rateLimit` table, `AdditionalFields` columns,
   indexes (matched by columns, not names), and with `database` / `serial` ids all core tables.
   Rules: a column is added `NOT NULL` only when it has a default the dialect accepts in `ADD COLUMN`;
   a required field **without** a default can only be added to an empty table, otherwise startup fails
   with `*gormadapter.RequiredColumnError` (give it a default, make it optional, or add and backfill the
   column yourself).
3. **Plugin migrators** (`Plugin.Migrator()`): plugins that still keep GORM structs (organization,
   two-factor, passkey, jwt) AutoMigrate their tables.
4. The registry migrator once more (GORM's SQLite migrator rebuilds a table to add a foreign key and drops
   its indexes).

A second start is a no-op. `verify` and `off` skip all four steps, including the plugin migrators, so with a
migration tool you create those plugins' tables yourself (run once in `auto` against a dev database and copy
them; they join the generated SQL when the plugins move onto the registry, missing-tasks 2.9). Don't switch a
database created from generated SQL back to `auto`: GORM's AutoMigrate would adjust column types and
defaults to its struct tags.

## Generating SQL

Public API (root package):

```go
reg, err := goauth.Schema(opts)                               // the registry SetupGoAuth would build
sql, err := goauth.GenerateSQL(opts, render.Postgres)         // desired state: CREATE TABLE / CREATE INDEX
plan, dialect, err := goauth.PlanMigration(ctx, opts)         // what opts.Conn lacks
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
