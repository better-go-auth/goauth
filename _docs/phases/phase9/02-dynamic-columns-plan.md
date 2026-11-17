# 02 – Dynamic columns (`additionalFields`) implementation plan

> **Read with [04-storage-agnostic-schema-and-migrations.md](04-storage-agnostic-schema-and-migrations.md).**
> The registry, input/output rules and compat decisions below stay valid. The storage parts (§4.4–4.7, the
> GORM-specific steps in §5) become implementation details of the GORM adapter, and the delivery order is
> replaced by doc 04 §7 so that MongoDB, `database/sql` (Bun, sqlx, pgx, sqlc, Ent) and Atlas are covered
> without re-implementing dynamic columns per backend.

How to give goauth better-auth's `additionalFields`, plugin `schema`, `fields` (column renames) and `modelName`
(table renames) with real database columns, building on the phase 8 research
([../phase8/README.md](../phase8/README.md)) but scoped to what the code base has today: one ORM (GORM) plus
the in-memory repositories.

---

## 1. What better-auth actually does

Source: `better-auth/dist/db/schema.mjs` (`getFields`, `parseInputData`, `parseUserOutput`) and
`@better-auth/core/db` (`getAuthTables`).

```ts
betterAuth({
  user: {
    modelName: "users",                        // table rename
    fields: { emailVerified: "is_verified" },  // column rename for core fields
    additionalFields: {
      loyaltyTier: { type: "string", defaultValue: "bronze", input: false },
      birthday:    { type: "date", required: false },
      tags:        { type: "string[]", returned: true },
    },
  },
  session: { additionalFields: { deviceName: { type: "string" } } },
  account: { additionalFields: { ... } },
  plugins: [phoneNumber()],                    // plugin.schema.user.fields.phoneNumber merged in
})
```

Rules the Go version must reproduce:

| Rule | Behaviour |
|---|---|
| Schema merge | core fields → `options.<model>.additionalFields` → every `plugin.schema.<model>.fields` (later wins). Applies to user, session, account; plugins can add whole tables. |
| Field attributes | `type` (`string`, `number`, `boolean`, `date`, `json`, `string[]`, `number[]`, or an enum array), `required`, `defaultValue` (value or function), `input` (default true), `returned` (default true), `unique`, `index`, `sortable`, `references {model, field, onDelete}`, `fieldName` (column name), `transform {input, output}`, `validator {input, output}`, `onUpdate`. |
| Input on create | key present + `input:false` → default applied if any, else `400 FIELD_NOT_ALLOWED "<key> is not allowed to be set"` when the value is truthy; validator failure → `400 VALIDATION_ERROR`; missing + default → default; missing + required → `400 MISSING_FIELD "<key> is required"`. |
| Input on update | same, but defaults and `required` are not applied. |
| Unknown keys | silently dropped (goauth currently rejects them with `FIELD_NOT_ALLOWED` – see §6). |
| Output | every field with `returned !== false` is included; optional missing fields are `null`. Applied to `/get-session`, sign-in/up responses, the cookie cache and plugin responses. |
| Where input is parsed | `/sign-up/email` body, `/update-user` body, `/update-session`, social/OTP sign-up (`rest` of the body), admin create-user `data`. |

---

## 2. Target design

```
               AuthConfig.User.AdditionalFields      Plugin.Schema()      core field defs
                              │                            │                    │
                              └──────────────┬─────────────┴────────────────────┘
                                             ▼
                             ┌───────────────────────────────┐
                             │  schema.Registry (immutable)   │  built once in SetupGoAuth
                             │  model → table, field → column │
                             └──────┬───────────┬────────────┘
                 input parsing      │           │ DDL diff                 output filtering
       ┌───────────────────────────┘           └───────────────┐   ┌──────────────────────────┐
       ▼                                                       ▼   ▼                          │
 schema.ParseInput(model, body, action)            migration.ColumnSync      dtos.UserFromModel(u, reg)
       │ map[field]any (validated)                 ADD COLUMN / INDEX        flattens u.Extra
       ▼
 models.User{ ...static fields..., Extra: map[string]any }
       │
       ▼
 repositories (GORM / memory) read+write static columns AND Extra columns
```

Key decisions:

1. **Physical columns, not a JSON blob.** Required for full compatibility: a TypeScript better-auth server
   sharing the database reads `loyaltyTier` from a real column. (Phase 8 doc 01 compares the options; this is
   its "hybrid" recommendation without the JSONB fallback, which can come later.)
2. **Static struct + `Extra` map.** Core and well-known fields stay typed Go fields (fast, compile-time safe);
   anything declared at runtime lives in `Extra map[string]any`. No code generation required.
3. **One registry drives everything**: input parsing, output filtering, migrations, column names and the
   repositories. Nothing else hard-codes field lists (today `updatableUserFields`,
   `config.DefaultUpdatableSessionFields` and the DTO structs each do).
4. **Plugins declare schema** instead of editing `models.User`. Existing typed plugin fields (role, banned,
   phoneNumber, twoFactorEnabled) are registered as *static* fields of their plugin's schema, so the registry
   knows them (output, migrations) while Go code keeps typed access.

---

## 3. API

### 3.1 Field definitions (`src/schema/field.go`, new package)

```go
package schema

type FieldType string

const (
    String, Number, Boolean, Date, JSON FieldType = "string", "number", "boolean", "date", "json"
    StringArray, NumberArray            FieldType = "string[]", "number[]"
)

// Field mirrors better-auth's DBFieldAttribute.
type Field struct {
    Type       FieldType
    Enum       []string          // type "string" restricted to these values (better-auth's enum array)
    Required   bool
    Default    any               // value, or func() any
    Input      *bool             // nil = true
    Returned   *bool             // nil = true
    Unique     bool
    Index      bool
    Sortable   bool
    FieldName  string            // column name override (better-auth fieldName / fields mapping)
    References *Reference        // {Model, Field, OnDelete}
    Validate   func(v any) (any, error)   // validator.input; error message → VALIDATION_ERROR
    TransformIn, TransformOut func(v any) any
    OnUpdate   func() any        // value written on every update (e.g. updatedAt-like fields)
}

type Model struct {
    Name      string            // better-auth model name: "user", "session", ...
    TableName string            // modelName override
    Fields    map[string]Field  // JSON key → definition
}
```

### 3.2 Configuration

```go
config.UserOptions{
    ModelName:        "users",
    Fields:           map[string]string{"emailVerified": "is_verified"},
    AdditionalFields: map[string]schema.Field{
        "loyaltyTier": {Type: schema.String, Default: "bronze", Input: schema.False},
    },
}
// same for Session, Account (and Verification.ModelName/Fields)
```

The placeholder `ModelName`/`Fields`/`AdditionalFields` on `config.Session` (`// not supported`) become real.

### 3.3 Plugin schema

```go
// plugins/plugins-interface.go
type SchemaProvider interface {
    Schema() schema.PluginSchema // map[model]Model; new models = new tables
}
```

`SetupGoAuth` builds the registry from core + config + every `SchemaProvider`, then validates it
(duplicate columns, unknown references, a required field without default on an existing table → error).
Org, two-factor, passkey and jwt tables move to this declaration in a later step (§5 step 7).

### 3.4 Reading values in Go

```go
tier, ok := schema.Get[string](user, "loyaltyTier")
user.Set("loyaltyTier", "gold")            // validated against the registry on save

// optional typed view for apps that prefer structs:
type MyUser struct{ LoyaltyTier string `field:"loyaltyTier"` }
var mine MyUser
schema.Bind(user, &mine)
```

---

## 4. Implementation details per layer

### 4.1 Models (`src/models`)
- Add `Extra map[string]any \`gorm:"-" json:"-"\`` to `User`, `Session`, `Account` (and `Verification` for
  plugins that need it).
- `Session.DeviceToken/DeviceID/DeviceName/DeviceType` and the goauth user extras (`FirstName`, `Bio`, …) stay
  typed but are declared as built-in additional fields, which replaces the `updatableUserFields` allowlist and
  `Session.GoAuth.UpdatableFields`.

### 4.2 Input parsing (`src/schema/parse.go`)
Port `parseInputData` exactly (rules table in §1), returning `map[string]any` keyed by field name, split by
the caller into static updates (Go field names, for the existing repo `UpdateUser(map)` calls) and `Extra`.
Type coercion: JSON numbers → `float64`/`int64` per field, RFC 3339 strings → `time.Time` for `date`,
arrays validated element-wise, `json` kept as `json.RawMessage`.

Callers to switch over:
`auth.Service.SignUpEmail` (body `additionalProperties` are already accepted),
`auth.Service.UpdateUser` (`user_routes.go` already collects unknown keys), `UpdateSession`,
email-otp / magic-link / social / phone-number sign-up paths, admin `createUser.data`.

### 4.3 Output (`src/models/dtos/better_auth.go`)
- `UserFromModel(u)` → `UserFromModel(u, reg)` (keep the old signature as a wrapper using a package-level
  default registry set by `SetupGoAuth`, to avoid touching every caller at once).
- `UserResponse` gets `Extra map[string]any` and a `MarshalJSON` that writes static fields then every
  `returned` extra (`null` when absent, like `buildSyntheticUserOutput`), and drops `returned:false` static
  fields too.
- The cookie cache payload (`CachedSessionPayload`) and secondary-storage session cache store the same flattened
  JSON, so cached sessions include extras.

### 4.4 Column naming (`src/common/gormutil/naming.go`)
- Extend `NamingStrategy` with `ColumnName(table, field string)` overrides from the registry, so
  `Fields: {"emailVerified": "is_verified"}` renames core columns without touching struct tags.
- The same hook implements a global `GoAuth.ColumnCase = "snake" | "camel"` option (camel = better-auth's
  default Kysely/Drizzle layout, required to share a database with a default TypeScript setup – see
  [03-missing-features-and-compat-gaps.md](03-missing-features-and-compat-gaps.md) §1).

### 4.5 Migrations (`src/models/migration/columns.go`)
For each registry model:
1. `AutoMigrate` the static struct as today.
2. Read existing columns with `db.Migrator().ColumnTypes(table)`.
3. For each missing extra field emit dialect DDL (`ALTER TABLE … ADD COLUMN`) with the mapped SQL type:

| type | Postgres | MySQL | SQLite |
|---|---|---|---|
| string | `text` (`varchar(255)` if unique/index) | `varchar(255)` / `text` | `text` |
| number | `bigint` or `double precision` (`Field.Float`) | `bigint` / `double` | `integer` / `real` |
| boolean | `boolean` | `tinyint(1)` | `integer` |
| date | `timestamptz` | `datetime(3)` | `datetime` |
| json, string[], number[] | `jsonb` | `json` | `text` (JSON string, as better-auth stores arrays on SQLite) |

4. `NOT NULL` only with a default (`ADD COLUMN … NOT NULL DEFAULT …`); a required field without a default on a
   non-empty table is a setup error with a clear message.
5. Create `UNIQUE`/regular indexes; foreign keys for `References` on Postgres/MySQL.
6. Never drop or alter existing columns automatically. Provide `goauth migrate --dry-run` output (SQL text) so
   teams that run migrations separately can copy it, like better-auth's `generate`.

### 4.6 GORM repositories (`src/app/repository/gormauth`)
- **Create:** build one `map[string]any` keyed by column name from the struct (via `stmt.Schema.Fields`) plus
  `Extra`, and `db.Table(table).Create(map)`. One statement, so `NOT NULL` extras work.
- **Read:** v1 – `Take(&user)` then, only when the model has extras, `Select(extraColumns).Take(&row)` into a
  `map[string]any` and decode with the registry (two queries, simple and correct).
  v2 – a single query scanned through `Rows()` into the struct fields and the extra map using
  `schema.Field.Set` (do this once the contract tests exist).
- **Update:** `UpdateUser(id, map)` already takes a map; translate field names → columns with the registry
  (static Go names keep working) and apply `OnUpdate` fields.
- **Queries:** `ListUsers` search/sort accept registry fields marked `Sortable` (replaces the hard-coded
  `UserListField` switch).

### 4.7 Memory repositories
Store `Extra` alongside the struct; enforce `Unique` extras the way `phoneTaken` does; `applyUpdates` routes
unknown keys to `Extra` only if the registry declares them.

---

## 5. Delivery steps

| # | Step | Done when |
|---|---|---|
| 1 | `src/schema` package: `Field`, `Model`, `Registry`, merge + validation, unit tests | registry builds from config + plugins; conflicts reported |
| 2 | `ParseInput` port with table-driven tests copied from better-auth's rules | identical error codes/messages for every rule in §1 |
| 3 | `Extra` on models, DTO flattening, cookie-cache/secondary-storage round trip | `/get-session` returns extras, `returned:false` hidden |
| 4 | Migration column sync for SQLite/Postgres/MySQL (testcontainers) | adds columns/indexes idempotently, dry-run prints SQL |
| 5 | GORM + memory repositories read/write extras; `repotest` contract extended per type | contract passes on 3 dialects + memory |
| 6 | Wire sign-up, update-user, update-session, plugin sign-ups, admin create-user | client test: `signUp.email({ …, loyaltyTier })` with `inferAdditionalFields` |
| 7 | Plugins declare schema (`SchemaProvider`); move phone/two-factor/admin columns out of the hard-coded struct into plugin schemas (keep typed accessors) | users without the phone plugin get no `phone_number` column |
| 8 | `Fields`/`ModelName` mapping + `ColumnCase` option | shared-DB test with a TypeScript server using the same options |

Steps 1–3 are pure Go and safe to ship first; step 7 is the only one with a migration risk (columns already
exist in deployed databases, so plugin schemas must treat them as present, never drop them).

---

## 6. Compatibility decisions to make

1. **Unknown keys on update-user.** better-auth drops them silently; goauth returns `FIELD_NOT_ALLOWED`.
   Recommendation: follow better-auth (drop) in compat mode, keep strict rejection behind
   `User.GoAuth.RejectUnknownFields` because it catches client typos.
2. **Number precision.** better-auth numbers are JS doubles. Default `number` to `float64` in JSON output and
   `bigint` storage only when `Field.Integer` is set.
3. **Dates.** Output with the existing `dtos.Time` (millisecond ISO) so extras match core timestamps.
4. **Arrays on Postgres.** better-auth's Kysely adapter stores `string[]` as JSON text on SQLite and native
   arrays/JSON depending on the adapter on Postgres. Default to `jsonb` and make it configurable per field
   (`Field.Storage = "json" | "native"`).

---

## 7. Testing

- Table tests for `ParseInput` mirroring better-auth's own `parse-input` tests (required, defaults, functions,
  input:false with/without default, validators, transforms, update vs create).
- `repotest` contract: every type round-trips through GORM (3 dialects) and memory; unique/indexed extras.
- Migration tests: add field → column exists; restart → no-op; required without default on non-empty table →
  setup error.
- Client tests (`src/tests/compat/client`): `createAuthClient({ plugins: [inferAdditionalFields({...})] })`
  signs up with extras, `updateUser` changes them, `getSession` returns them.
- Shared-database test with the TypeScript reference server configured with the same `additionalFields`.
