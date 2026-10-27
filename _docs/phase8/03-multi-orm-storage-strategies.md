# 03: Multi-ORM Storage & Query Strategies

## 1. Multi-ORM Storage Integration Architecture

In Phase 7, we designed clean repository interfaces (`IUserRepo`, `ISessionRepo`, `IOAuthAccountRepo`, `IVerificationRepo`). In Phase 8, we extend these repositories to handle dynamic additional fields across all supported data access libraries.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           IUserRepo with Custom Fields                          │
│   CreateUser(ctx, user *models.User) (*models.User, error)                      │
│   FindUserByID(ctx, id string) (*models.User, error)                            │
│   UpdateUser(ctx, id string, data map[string]interface{}) (*models.User, error)│
└────────────────────────────────────────┬────────────────────────────────────────┘
                                         │
        ┌───────────────┬────────────────┼───────────────┬────────────────┐
        ▼               ▼                ▼               ▼                ▼
   ┌─────────┐     ┌─────────┐     ┌───────────┐    ┌─────────┐      ┌─────────┐
   │  GORM   │     │   Bun   │     │ stdsql /  │    │  sqlc   │      │   Ent   │
   │ Adapter │     │ Adapter │     │   sqlx    │    │ Adapter │      │ Adapter │
   └─────────┘     └─────────┘     └───────────┘    └─────────┘      └─────────┘
```

The repository layer abstracts storage details: callers pass or receive `*models.User`, and the adapter takes care of querying, serializing, and hydrating `user.CustomFields`.

---

## 2. GORM Storage Strategy (`gormauth`)

GORM supports dynamic column scanning and map-based updates natively through its statement builder and clause system.

### 2.1. Creating a User with Custom Columns
```go
func (r *UserRepo) CreateUser(ctx context.Context, u *models.User) (*models.User, error) {
    if u.ID == "" {
        u.ID = models.NewID()
    }
    db := gormutil.GetDB(ctx, r.db)

    if r.storageMode == StorageModeJSON {
        // Mode A: JSON Column (models.User has CustomFields CustomFields `gorm:"type:json"`)
        if err := db.Create(u).Error; err != nil {
            return nil, normalizeGormError(err)
        }
        return u, nil
    }

    // Mode B: Physical Columns
    // Convert base user struct to map and merge custom fields
    userMap := structToMap(u)
    for k, v := range u.CustomFields {
        colName := r.getColumnName(k)
        userMap[colName] = v
    }

    if err := db.Table(models.ResolveTableName(nil, models.ModelUser)).Create(userMap).Error; err != nil {
        return nil, normalizeGormError(err)
    }
    return u, nil
}
```

### 2.2. Querying Custom Columns with GORM
```go
func (r *UserRepo) FindUserByID(ctx context.Context, id string) (*models.User, error) {
    db := gormutil.GetDB(ctx, r.db)
    u := new(models.User)

    if r.storageMode == StorageModeJSON {
        if err := db.Where("id = ? AND deleted_at IS NULL", id).First(u).Error; err != nil {
            return nil, normalizeGormError(err)
        }
        return u, nil
    }

    // Mode B: Physical Columns
    // Query row into a map to extract custom columns alongside core fields
    var row map[string]interface{}
    err := db.Table(models.ResolveTableName(nil, models.ModelUser)).
        Where("id = ? AND deleted_at IS NULL", id).
        Take(&row).Error
    if err != nil {
        return nil, normalizeGormError(err)
    }

    return mapToUserWithCustomFields(row, r.customFieldSchema), nil
}
```

---

## 3. Bun Storage Strategy (`bunauth`)

Bun is SQL-first, exceptionally fast, and provides direct expressions for dynamic column queries.

### 3.1. Inserting with Bun
```go
func (r *UserRepo) CreateUser(ctx context.Context, u *models.User) (*models.User, error) {
    if u.ID == "" {
        u.ID = models.NewID()
    }
    db := r.getDB(ctx)

    if r.storageMode == StorageModeJSON {
        _, err := db.NewInsert().Model(u).Exec(ctx)
        return u, normalizeBunError(err)
    }

    // Mode B: Physical Columns
    q := db.NewInsert().Model(u)
    for fieldName, val := range u.CustomFields {
        colName := r.getColumnName(fieldName)
        q = q.Value(colName, "?", val)
    }

    _, err := q.Exec(ctx)
    if err != nil {
        return nil, normalizeBunError(err)
    }
    return u, nil
}
```

### 3.2. Selecting with Dynamic Columns in Bun
```go
func (r *UserRepo) FindUserByEmail(ctx context.Context, email string) (*models.User, error) {
    u := new(models.User)
    q := r.getDB(ctx).NewSelect().Model(u).
        Where("LOWER(email) = LOWER(?)", strings.TrimSpace(email)).
        Where("deleted_at IS NULL")

    // In physical column mode, add extra columns to SELECT
    if r.storageMode == StorageModeColumns {
        for _, col := range r.physicalColumns {
            q = q.Column(col)
        }
    }

    if err := q.Scan(ctx); err != nil {
        return nil, normalizeBunError(err)
    }
    return u, nil
}
```

---

## 4. Standard `database/sql` & `sqlx` Strategy (`stdsql`)

For zero-dependency and `sqlx` deployments, the query builder constructs dynamic column lists while parameterizing all values.

### 4.1. Dynamic Query Assembly
```go
type QueryBuilder struct {
    dialect Dialect
    columns []string
}

func (qb *QueryBuilder) BuildSelectUser(whereClause string) string {
    baseCols := "id, name, email, email_verified, image, role, banned, created_at, updated_at, deleted_at"
    if len(qb.columns) > 0 {
        baseCols += ", " + strings.Join(qb.columns, ", ")
    }
    query := fmt.Sprintf("SELECT %s FROM users WHERE %s", baseCols, whereClause)
    return qb.dialect.Rebind(query)
}
```

### 4.2. Scanning with `sqlx`
`sqlx` makes custom column scanning trivial: when `models.User` has `CustomFields`, `sqlx.MapScan` or a custom slice scanner populates standard fields and loads remaining columns into `CustomFields`:

```go
func (r *UserRepo) FindUserByID(ctx context.Context, id string) (*models.User, error) {
    query := r.qb.BuildSelectUser("id = ? AND deleted_at IS NULL")
    rows, err := r.executor(ctx).QueryContext(ctx, query, id)
    if err != nil {
        return nil, normalizeSQLError(err)
    }
    defer rows.Close()

    if !rows.Next() {
        return nil, autherr.ErrNotFound
    }

    // Dynamic scanner scans known columns into struct, unknown into map
    return scanUserWithCustomColumns(rows, r.schema)
}
```

---

## 5. `sqlc` Storage Strategy (`sqlcauth`)

`sqlc` compiles static SQL at build time. Because SQL is verified ahead of time, dynamic columns must be handled according to one of two patterns:

### Option A: Schemaless JSON Column (Zero Codegen Overhead)
`sqlc` compiles a `custom_fields JSONB` column directly into Go:
```sql
-- queries/users.sql
-- name: CreateUser :one
INSERT INTO users (id, name, email, custom_fields)
VALUES ($1, $2, $3, $4)
RETURNING *;
```
The adapter serializes `models.User.CustomFields` to JSON, passes it to the `sqlc` query, and deserializes the returned JSON. This gives **100% type-safe compilation** with zero manual SQL editing.

### Option B: Extensible Schema Template
If real database columns are required with `sqlc`:
1. `goauth` provides an extensible `schema.sql` template.
2. The user runs a code generation CLI command:
   ```bash
   go run github.com/better-go-auth/goauth/cmd/codegen --add-field "phoneNumber:string"
   ```
   This appends `phone_number VARCHAR(255)` to `schema.sql` and re-runs `sqlc generate`.

---

## 6. `Ent` Storage Strategy (`entauth`)

In Ent, additional fields are defined directly in the Ent schema or via an Ent **Mixin**:

```go
// ent/schema/user_custom_mixin.go
package schema

import (
    "entgo.io/ent"
    "entgo.io/ent/schema/field"
    "entgo.io/ent/schema/mixin"
)

type CustomFieldsMixin struct {
    mixin.Schema
}

func (CustomFieldsMixin) Fields() []ent.Field {
    return []ent.Field{
        field.String("phone_number").Optional(),
        field.String("loyalty_tier").Default("standard"),
        field.JSON("custom_fields", map[string]interface{}{}).Optional(),
    }
}
```
When `ent generate` is executed, Ent creates fully type-safe getters and setters (`user.SetPhoneNumber("+123456")`), and the `entauth` adapter maps them to `models.User.CustomFields`.
