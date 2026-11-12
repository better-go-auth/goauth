# 06: Physical Columns Repository Architecture

## 1. Physical Columns Data Flow in Repositories

When using physical column storage, the database stores each custom attribute as an independent column in the row:

```
Database Row in "users" Table
┌───────────┬───────────────┬───────────────────┬────────────────┬─────┐
│ id        │ name          │ email             │ phone_number   │ age │
├───────────┼───────────────┼───────────────────┼────────────────┼─────┤
│ usr_abc   │ Alice Smith   │ alice@example.com │ +1-555-0199    │ 29  │
└─────┬─────┴───────┬───────┴─────────┬─────────┴────────┬───────┴──┬──┘
      │             │                 │                  │          │
      ▼             ▼                 ▼                  ▼          ▼
Core Go Struct Fields              Dynamically Scanned into CustomFields
┌─────────────────────────────────┐┌───────────────────────────────────┐
│ u.ID = "usr_abc"                ││ u.CustomFields["phoneNumber"]     │
│ u.Name = "Alice Smith"          ││                 = "+1-555-0199"   │
│ u.Email = "alice@example.com"   ││ u.CustomFields["age"] = 29.0      │
└─────────────────────────────────┘└───────────────────────────────────┘
```

The domain repository interfaces (`repo_interfaces.IUserRepo`, `ISessionRepo`) accept and return `*models.User` and `*models.Session`. The repository adapters are responsible for:
1. Translating camelCase field names (`phoneNumber`) to snake_case column names (`phone_number`).
2. Including physical custom columns in dynamic `SELECT` statements.
3. Hydrating scanned physical columns into `user.CustomFields`.
4. Inserting and updating physical columns in `INSERT` and `UPDATE` statements.

---

## 2. GORM Physical Column Implementation (`gormauth`)

In GORM, structs with static fields are the default, but GORM also provides low-level reflection and table mapping for dynamic columns.

### 2.1. Repository Setup & Column Metadata
The GORM repository retains a registry of configured physical columns:

```go
package gormauth

import (
    "context"
    "fmt"
    "strings"
    "time"

    "github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
    "github.com/better-go-auth/goauth/src/common/autherr"
    "github.com/better-go-auth/goauth/src/common/gormutil"
    "github.com/better-go-auth/goauth/src/models"
    "gorm.io/gorm"
)

type UserRepo struct {
    db             *gorm.DB
    physicalCols   []string                    // e.g. ["phone_number", "age"]
    colToFieldMap  map[string]string           // "phone_number" -> "phoneNumber"
    fieldToColMap  map[string]string           // "phoneNumber" -> "phone_number"
}

func NewUserRepo(db *gorm.DB, fields map[string]models.FieldConfig) repo_interfaces.IUserRepo {
    r := &UserRepo{
        db:            db,
        colToFieldMap: make(map[string]string),
        fieldToColMap: make(map[string]string),
    }
    for fieldName, cfg := range fields {
        colName := cfg.ColumnName
        if colName == "" {
            colName = toSnakeCase(fieldName)
        }
        r.physicalCols = append(r.physicalCols, colName)
        r.colToFieldMap[strings.ToLower(colName)] = fieldName
        r.fieldToColMap[fieldName] = colName
    }
    return r
}
```

### 2.2. Inserting with Physical Columns in GORM
To insert dynamic columns alongside standard struct fields, `UserRepo` converts the user into an insert map:

```go
func (r *UserRepo) CreateUser(ctx context.Context, u *models.User) (*models.User, error) {
    if u.ID == "" {
        u.ID = models.NewID()
    }
    u.Email = strings.ToLower(strings.TrimSpace(u.Email))
    now := time.Now().UTC()
    u.CreatedAt = now
    u.UpdatedAt = now

    // 1. Build insert dictionary with standard columns
    insertData := map[string]interface{}{
        "id":             u.ID,
        "name":           u.Name,
        "email":          u.Email,
        "email_verified": u.EmailVerified,
        "image":          u.Image,
        "role":           string(u.Role),
        "banned":         u.Banned,
        "ban_reason":     u.BanReason,
        "ban_expires":    u.BanExpires,
        "created_at":     u.CreatedAt,
        "updated_at":     u.UpdatedAt,
    }

    // 2. Append physical custom columns from u.CustomFields
    if u.CustomFields != nil {
        for fieldName, val := range u.CustomFields {
            if colName, ok := r.fieldToColMap[fieldName]; ok {
                insertData[colName] = val
            }
        }
    }

    // 3. Execute INSERT on the users table
    db := gormutil.GetDB(ctx, r.db)
    tableName := models.ResolveTableName(nil, models.ModelUser)
    if err := db.Table(tableName).Create(insertData).Error; err != nil {
        return nil, normalizeGormError(err)
    }

    return u, nil
}
```

### 2.3. Querying & Scanning Physical Columns in GORM
When querying by ID or Email, `UserRepo` queries the row into a raw map or executes a custom scanner:

```go
func (r *UserRepo) FindUserByID(ctx context.Context, id string) (*models.User, error) {
    db := gormutil.GetDB(ctx, r.db)
    tableName := models.ResolveTableName(nil, models.ModelUser)

    var row map[string]interface{}
    err := db.Table(tableName).
        Where("id = ? AND deleted_at IS NULL", id).
        Take(&row).Error
    if err != nil {
        if errors.Is(err, gorm.ErrRecordNotFound) {
            return nil, autherr.ErrNotFound
        }
        return nil, err
    }

    return r.hydrateUserFromRow(row), nil
}

func (r *UserRepo) hydrateUserFromRow(row map[string]interface{}) *models.User {
    u := &models.User{
        CustomFields: make(models.CustomFields),
    }

    // Core fields
    if id, ok := row["id"].(string); ok { u.ID = id }
    if name, ok := row["name"].(string); ok { u.Name = name }
    if email, ok := row["email"].(string); ok { u.Email = email }
    if verified, ok := row["email_verified"].(bool); ok { u.EmailVerified = verified }
    // ... dates and other standard fields ...

    // Physical custom fields extraction
    for colName, fieldName := range r.colToFieldMap {
        if val, exists := row[colName]; exists && val != nil {
            u.CustomFields[fieldName] = normalizeValue(val)
        }
    }

    return u
}
```

### 2.4. Updating Physical Columns in GORM
```go
func (r *UserRepo) UpdateUser(ctx context.Context, id string, data map[string]interface{}) (*models.User, error) {
    updateData := make(map[string]interface{})

    for k, v := range data {
        // Map field name to column name (either standard or custom)
        if colName, ok := r.fieldToColMap[k]; ok {
            updateData[colName] = v
        } else {
            updateData[toSnakeCase(k)] = v
        }
    }
    updateData["updated_at"] = time.Now().UTC()

    db := gormutil.GetDB(ctx, r.db)
    tableName := models.ResolveTableName(nil, models.ModelUser)
    res := db.Table(tableName).Where("id = ? AND deleted_at IS NULL", id).Updates(updateData)
    if res.Error != nil {
        return nil, normalizeGormError(res.Error)
    }
    if res.RowsAffected == 0 {
        return nil, autherr.ErrNotFound
    }

    return r.FindUserByID(ctx, id)
}
```

---

## 3. Bun Physical Column Implementation (`bunauth`)

Bun excels at dynamic column selection and insertion through its fluent API (`.ColumnExpr()`, `.Value()`).

### 3.1. Inserting with Bun
```go
func (r *UserRepo) CreateUser(ctx context.Context, u *models.User) (*models.User, error) {
    if u.ID == "" {
        u.ID = models.NewID()
    }
    u.Email = strings.ToLower(strings.TrimSpace(u.Email))
    u.CreatedAt = time.Now().UTC()
    u.UpdatedAt = u.CreatedAt

    q := r.getDB(ctx).NewInsert().Model(u)

    // Append each physical column dynamically
    if u.CustomFields != nil {
        for fieldName, val := range u.CustomFields {
            if colName, ok := r.fieldToColMap[fieldName]; ok {
                q = q.Value(colName, "?", val)
            }
        }
    }

    _, err := q.Exec(ctx)
    if err != nil {
        return nil, normalizeBunError(err)
    }
    return u, nil
}
```

### 3.2. Selecting with Physical Columns in Bun
```go
func (r *UserRepo) FindUserByID(ctx context.Context, id string) (*models.User, error) {
    u := new(models.User)
    u.CustomFields = make(models.CustomFields)

    // Query core model fields
    q := r.getDB(ctx).NewSelect().Model(u).
        Where("id = ?", id).
        Where("deleted_at IS NULL")

    // If there are no physical columns, standard scan works
    if len(r.physicalCols) == 0 {
        if err := q.Scan(ctx); err != nil {
            return nil, normalizeBunError(err)
        }
        return u, nil
    }

    // When physical columns exist, query row into a map to extract them
    var row map[string]interface{}
    err := r.getDB(ctx).NewSelect().
        Table(models.ResolveTableName(nil, models.ModelUser)).
        Where("id = ?", id).
        Where("deleted_at IS NULL").
        Scan(ctx, &row)
    if err != nil {
        return nil, normalizeBunError(err)
    }

    return r.hydrateUserFromRow(row), nil
}
```

---

## 4. Standard `database/sql` & `sqlx` Implementation (`stdsql`)

`stdsql` and `sqlx` provide the cleanest low-level control. Dynamic queries are generated with parameterized values and scanned via standard `*sql.Rows`.

### 4.1. Dynamic Query Builder
```go
type QueryBuilder struct {
    dialect      Dialect
    physicalCols []string
}

func (qb *QueryBuilder) BuildSelect(table, whereClause string) string {
    cols := []string{
        "id", "name", "email", "email_verified", "image", "role",
        "banned", "ban_reason", "ban_expires", "created_at", "updated_at", "deleted_at",
    }
    cols = append(cols, qb.physicalCols...)
    query := fmt.Sprintf("SELECT %s FROM %s WHERE %s", strings.Join(cols, ", "), table, whereClause)
    return qb.dialect.Rebind(query)
}

func (qb *QueryBuilder) BuildInsert(table string, customColNames []string) (string, []string) {
    cols := []string{
        "id", "name", "email", "email_verified", "image", "role",
        "banned", "created_at", "updated_at",
    }
    cols = append(cols, customColNames...)

    placeholders := make([]string, len(cols))
    for i := range placeholders {
        placeholders[i] = "?"
    }

    raw := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", table, strings.Join(cols, ", "), strings.Join(placeholders, ", "))
    return qb.dialect.Rebind(raw), cols
}
```

### 4.2. Scanning Any Column Dynamic Loop
The standard library row scanner iterates over `rows.Columns()`:

```go
func scanRowWithCustomColumns(rows *sql.Rows, colToFieldMap map[string]string) (*models.User, error) {
    cols, err := rows.Columns()
    if err != nil {
        return nil, err
    }

    // Allocate scan destinations
    values := make([]interface{}, len(cols))
    valuePtrs := make([]interface{}, len(cols))
    for i := range values {
        valuePtrs[i] = &values[i]
    }

    if err := rows.Scan(valuePtrs...); err != nil {
        return nil, err
    }

    u := &models.User{
        CustomFields: make(models.CustomFields),
    }

    for i, colName := range cols {
        val := values[i]
        if val == nil {
            continue
        }

        colLower := strings.ToLower(colName)
        switch colLower {
        case "id":
            u.ID = stringValue(val)
        case "name":
            u.Name = stringValue(val)
        case "email":
            u.Email = stringValue(val)
        case "email_verified":
            u.EmailVerified = boolValue(val)
        case "created_at":
            u.CreatedAt = timeValue(val)
        case "updated_at":
            u.UpdatedAt = timeValue(val)
        default:
            // Custom physical column
            if fieldName, isCustom := colToFieldMap[colLower]; isCustom {
                u.CustomFields[fieldName] = normalizeScanValue(val)
            }
        }
    }

    return u, nil
}
```

---

## 5. `sqlc` & `Ent` Physical Columns Strategies

Because `sqlc` and `Ent` compile static code at build-time, handling dynamic physical columns requires compile-time code synchronization:

### 5.1. `sqlc` Physical Columns Workflow
1. When a user defines additional fields, the developer runs a code generation utility:
   ```bash
   go run cmd/goauth codegen --add-field "phoneNumber:string"
   ```
2. The CLI appends the physical column to `schema/schema_postgres.sql`:
   ```sql
   ALTER TABLE users ADD COLUMN phone_number VARCHAR(255);
   ```
3. `sqlc generate` re-runs automatically, generating `db.User.PhoneNumber`.
4. The `sqlcauth` repository mapper copies `db.User.PhoneNumber` into `models.User.CustomFields["phoneNumber"]`.

### 5.2. `Ent` Physical Columns Workflow
1. In Ent, the developer declares physical columns using an Ent **Mixin**:
   ```go
   // ent/schema/user_extra.go
   func (UserExtraMixin) Fields() []ent.Field {
       return []ent.Field{
           field.String("phone_number").Optional().Unique(),
           field.Float("age").Optional(),
       }
   }
   ```
2. Run `go generate ./ent`.
3. Ent generates the typed builders and migrations automatically via Atlas.
4. The `entauth` adapter copies Ent entity properties to/from `models.User.CustomFields`.
